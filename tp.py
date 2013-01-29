#!/usr/bin/python

import errno
import simplejson
import sys

default_prefs = {
  'browser.formfill.enable' : 'true',
  'browser.privatebrowsing.autostart' : 'false',
  'browser.safebrowsing.enabled' : 'true',
  'browser.safebrowsing.malware.enabled' : 'true',
  'browser.search.defaultenginename' : 'chrome???browser-region?locale?region.properties',
  'browser.search.suggest.enabled' : 'true',
  'browser.urlbar.autocomplete.enabled' : 'true',
  'browser.urlbar.default.behavior' : '0',
  'network.cookie.cookieBehavior' : '0',
  'network.cookie.lifetimePolicy' : '0',
  'places.history.enabled' : 'true',
  'privacy.clearOnShutdown.cache' : 'true',
  'privacy.clearOnShutdown.cookies' : 'true',
  'privacy.clearOnShutdown.downloads' : 'true',
  'privacy.clearOnShutdown.formdata' : 'true',
  'privacy.clearOnShutdown.history' : 'true',
  'privacy.clearOnShutdown.offlineApps' : 'false',
  'privacy.clearOnShutdown.passwords' : 'false',
  'privacy.clearOnShutdown.sessions' : 'true',
  'privacy.clearOnShutdown.siteSettings' : 'false',
  'privacy.cpd.cache' : 'true',
  'privacy.cpd.cookies' : 'true',
  'privacy.cpd.downloads' : 'true',
  'privacy.cpd.formdata' : 'true',
  'privacy.cpd.history' : 'true',
  'privacy.cpd.offlineApps' : 'false',
  'privacy.cpd.passwords' : 'false',
  'privacy.cpd.sessions' : 'true',
  'privacy.cpd.siteSettings' : 'false',
  'privacy.donottrackheader.enabled' : 'false',
  'privacy.sanitize.sanitizeOnShutdown' : 'false',
  'security.ask_for_password' : '0',
  'security.default_personal_cert' : 'Ask Every Time',
  'security.enable_ssl3' : 'true',
  'security.enable_tls' : 'true',
  'security.OCSP.enabled' : '1',
  'security.OCSP.require' : 'false',
  'security.password_lifetime' : '30',
  'security.remember_cert_checkbox_default_setting' : 'true',
  'security.warn_entering_weak' : 'true',
  'security.warn_entering_weak.show_once' : 'true',
  'security.warn_viewing_mixed' : 'false',
  'security.warn_viewing_mixed.show_once' : 'true',
  'signon.rememberSignons' : 'true',
  'xpinstall.whitelist.required' : 'true',
}

password_stats = {
  'Total Passwords',
  'total sites',
  'most used'
  # Ignore histogram data for now
}

pref_counts = {}
errors = {'gooduser' : 0, 'baduser': 0, 'baduser_nosplit': 0, 'baduser_noevents': 0, 'gooduser_prefs' : 0, 'gooduser_password' : 0}
pref_changed = {}
search = {}
days = {}
cookies = {}
num_passwords_hist = [0] * 1000
num_sites_hist = [0] * 1000
highest_reuse_hist = [0] * 1000
ratio_hist = []


def init_maps():
  for p in default_prefs:
    pref_changed[p] = 0
    pref_counts[p] = 0


def process_security_prefs(e, already_seen):
  prefname = e[2]
  prefvalue = e[3]
  timestamp = e[4]
  # Use a canary to see how many days of data we got
  #if prefname == 'browser.formfill.enable':
  #  num_days += 1
  if prefname in already_seen:
    if prefvalue != already_seen[prefname]:
      pref_changed[prefname] += 1
  else:
    already_seen[prefname] = prefvalue
    if prefname == 'network.cookie.cookieBehavior':
      if prefvalue not in cookies:
        cookies[prefvalue] = 0
      cookies[prefvalue] += 1
    if default_prefs[prefname] != prefvalue:
      if prefname == 'browser.search.defaultenginename':
        if prefvalue not in search:
          search[prefvalue] = 0
        search[prefvalue] += 1
      pref_counts[prefname] += 1
  # How many days did the study run?
  #if num_days not in days:
  #  days[num_days] = 0
  #days[num_days] += 1
  # There's a bug here, many users have more than 10 days of data
  #if num_days > 10:
  #  print "numdays", uid, num_days


def process_password_stats(num_passwords, num_sites, highest_reuse):
  if num_passwords < num_sites:
    assert highest_reuse > 1, "Stats don't make sense"
  num_passwords_hist[int(num_passwords)] += 1
  num_sites_hist[int(num_sites)] += 1
  if highest_reuse != '-Infinity':
    highest_reuse_hist[int(highest_reuse)] += 1
  if num_sites > 0 and num_passwords <= num_sites:
    ratio_hist.append(num_sites/float(num_passwords))
  elif num_passwords > num_sites:
    print "too many passwords for this many sites", num_passwords, num_sites


def process_one_user(data, sample_count):
  buf = data.partition('\t')
  if (len(buf) != 3):
    errors['baduser_nosplit'] += 1
    return
  uid = buf[0]
  user_data = buf[2]
  try:
    d = simplejson.loads(user_data)
  except simplejson.JSONDecodeError, e:
    errors['baduser'] += 1
    return
  events = d.get('events')
  if not events:
    errors['baduser_noevents'] += 1
    return
  errors['gooduser'] += 1
  already_seen = {}
  num_passwords = -1
  num_sites = -1
  highest_reuse = 0
  prefs_seen = False
  password_seen = False
  for e in events:
    if e[0] != 3:
      continue
    if e[1] == 'Security Pref':
      prefs_seen = True
      process_security_prefs(e, already_seen)
    elif e[2] in password_stats:
      password_seen = True
      if e[2] == 'Total Passwords':
        num_passwords = int(e[3])
      elif e[2] == 'total sites':
        num_sites = int(e[3])
      elif e[2] == 'most used':
        if e[3] != '-Infinity':
          highest_reuse = int(e[3])
        else:
          highest_reuse = 0
      else:
        print "couldn't parse", e
  if password_seen:
    errors['gooduser_password'] += 1
    assert num_passwords >= 0, "Didn't get num passwords: %s" % uid
    assert num_sites >= 0, "Didn't get num_sites: %s" % uid
    process_password_stats(num_passwords, num_sites, highest_reuse)
  if prefs_seen:
    errors['gooduser_prefs'] += 1


def finish():
  f = open('num_passwords.csv', 'w')
  for i in range(len(num_passwords_hist)):
    f.write('%d, %d\n' % (i, num_passwords_hist[i]))
  f.close()

  f = open('num_sites.csv', 'w')
  for i in range(len(num_sites_hist)):
    f.write('%d, %d\n' % (i, num_sites_hist[i]))
  f.close()

  f = open('num_reuse.csv', 'w')
  for i in range(len(highest_reuse_hist)):
    f.write('%d, %d\n' % (i, highest_reuse_hist[i]))
  f.close()

  f = open('password_ratio.csv', 'w')
  for i in range(len(ratio_hist)):
    f.write('%d, %f\n' % (i, ratio_hist[i]))
  f.close()

  f = open('pref_counts.csv', 'w')
  for p in sorted(pref_counts, key=pref_counts.get):
    f.write('%s, %d\n' % (p, pref_counts[p],))
  f.close()

  f = open('pref_changed.csv', 'w')
  for p in sorted(pref_changed, key=pref_changed.get):
    f.write('%s, %d\n' % (p, pref_changed[p],))
  f.close()
  f = open('search_engines.csv', 'w')
  for s in sorted(search, key=search.get):
    f.write('%s, %d\n' % (s, search[s],))
  f.close()
  #f = open('num_days.out', 'w')
  #for d in sorted(days, key=days.get):
  #  f.write('%s %d\n' % (d, days[d],))
  #f.close()
  f = open('cookie_behavior.csv', 'w')
  for c in sorted(cookies, key=cookies.get):
    f.write('%s, %d\n' % (c, cookies[c],))
  f.close()
  for e in errors:
    print e, errors[e]


try:
  f = open(sys.argv[1], 'r')
except error, e:
  sys.exit("Can't find file ", e)
init_maps()
sample_count = 0
for l in f.readlines():
  process_one_user(l, sample_count)
  sample_count += 1
finish()
f.close()
