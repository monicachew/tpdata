#!/usr/bin/python

import errno
import json
import sys
import numpy

# References: m-c/browser/components/preferences/{security,privacy}.xul
default_prefs = {
  # Remember forms
  'browser.formfill.enable' : 'true',
  # Start in PB mode
  'browser.privatebrowsing.autostart' : 'false',
  # Query Google for phishing and/or malware
  'browser.safebrowsing.enabled' : 'true',
  'browser.safebrowsing.malware.enabled' : 'true',
  # Default search engine
  'browser.search.defaultenginename' : 'chrome???browser-region?locale?region.properties',
  # Send keystrokes on search queries
  'browser.search.suggest.enabled' : 'true',
  # Autocomplete when typing in url bar
  'browser.urlbar.autocomplete.enabled' : 'true',
  # Use local history for autocomplete when typing in url bar
  'browser.urlbar.default.behavior' : '0',
  # Enable all cookies
  'network.cookie.cookieBehavior' : '0',
  # Max lifetime?
  'network.cookie.lifetimePolicy' : '0',
  # Remember my browsing and download history
  'places.history.enabled' : 'true',
  # Only matters if privacy.sanitizeOnShutdown is true
  # browser/components/preferences/sanitize.xul
  'privacy.clearOnShutdown.cache' : 'true',
  'privacy.clearOnShutdown.cookies' : 'true',
  'privacy.clearOnShutdown.downloads' : 'true',
  'privacy.clearOnShutdown.formdata' : 'true',
  'privacy.clearOnShutdown.history' : 'true',
  'privacy.clearOnShutdown.offlineApps' : 'false',
  'privacy.clearOnShutdown.passwords' : 'false',
  'privacy.clearOnShutdown.sessions' : 'true',
  'privacy.clearOnShutdown.siteSettings' : 'false',
  # browser/base/content/sanitize.xul
  # transmitted on browser/base/content/sanitize.js?
  'privacy.cpd.cache' : 'true',
  'privacy.cpd.cookies' : 'true',
  'privacy.cpd.downloads' : 'true',
  'privacy.cpd.formdata' : 'true',
  'privacy.cpd.history' : 'true',
  'privacy.cpd.offlineApps' : 'false',
  'privacy.cpd.passwords' : 'false',
  'privacy.cpd.sessions' : 'true',
  'privacy.cpd.siteSettings' : 'false',
  # Send DNT header
  'privacy.donottrackheader.enabled' : 'false',
  # Enforce clearOnShutdown prefs
  'privacy.sanitize.sanitizeOnShutdown' : 'false',
  # Non-zero if master password is enabled
  'security.ask_for_password' : '0',
  # Advanced settings, encryption tab
  'security.default_personal_cert' : 'Ask Every Time',
  'security.enable_ssl3' : 'true',
  'security.enable_tls' : 'true',
  'security.OCSP.enabled' : '1',
  'security.OCSP.require' : 'false',
  # Non-30 if master password is enabled
  'security.password_lifetime' : '30',
  # Advanced settings, encryption tab
  'security.remember_cert_checkbox_default_setting' : 'true',
  # Remember passwords
  'signon.rememberSignons' : 'true',
  # Don't prompt for installing xpis from file
  'xpinstall.whitelist.required' : 'true',
  # from browser/app/profile/firefox.js. Deprecated
  'security.warn_entering_weak.show_once': 'true',
  'security.warn_viewing_mixed.show_once': 'true',
}

password_stats = {
  'Total Passwords',
  'total sites',
  'most used'
  # Ignore histogram data for now
}

pref_counts = {}
errors = {
  'gooduser' : 0,
  'baduser': 0,
  'baduser_nosplit': 0,
  'baduser_noevents': 0,
  'gooduser_prefs' : 0,
  'gooduser_password' : 0,
  'not_default': 0,
  'accidental_user': 0,
  'accidental_user_one_site': 0,
  'accidental_user_one_password': 0,
  'counted': 0,
  'not_counted': 0,
}
pref_changed = {}
search = {}
cookies = {}
num_passwords_hist = [0] * 1000
num_sites_hist = [0] * 1000
highest_reuse_hist = [0] * 1000
num_days = [0] * 100
sites = []


def init_maps():
  for p in default_prefs:
    pref_changed[p] = 0
    pref_counts[p] = 0
  for i in range(30):
    sites.append([])


def process_password_stats(num_passwords, num_sites, highest_reuse, pwd_enabled):
  if not pwd_enabled:
    errors['accidental_user'] += 1
  if num_sites == 1:
    errors['accidental_user_one_site'] += 1
  if num_passwords == 1:
    errors['accidental_user_one_password'] += 1
  if num_passwords < num_sites:
    assert highest_reuse > 1, "Stats don't make sense"
  num_passwords_hist[int(num_passwords)] += 1
  num_sites_hist[int(num_sites)] += 1
  if highest_reuse != '-Infinity':
    highest_reuse_hist[int(highest_reuse)] += 1
  if num_sites < 30:
    sites[num_sites].append(num_passwords)
    errors["counted"] += 1
  else:
    errors["not_counted"] += 1

# Security prefs is an map of the form: {pref_name : pref_timeseries]} where
# pref_timeseries is an array of the form [[t1, v1]]
def process_security_prefs(security_prefs, uid):
  differs_from_default = False
  for p in security_prefs:
    if not p in default_prefs:
      continue
    timeseries = security_prefs[p]
    timeseries.sort()
    canary = timeseries[0][1]
    changes = 0
    # Count the number of times a pref has changed during the study
    for t in timeseries:
      if t[1] != canary:
        changes += 1
        canary = t[1]
    pref_changed[p] += changes
    # Count the number of days the study spans
    earliest = int(timeseries[0][0])
    latest = int(timeseries[-1][0])
    USEC_PER_DAY = 24 * 60 * 60 * 1000 * 1000
    delta = int((latest - earliest) / USEC_PER_DAY)
    num_days[delta] += 1;
    # Count differences from default pref, based on the first reading
    pref_value = timeseries[0][1]
    if default_prefs[p] != pref_value:
      pref_counts[p] += 1
      differs_from_default = True
    # Count some preferences separately
    if 'network.cookie.cookieBehavior' == p:
      if pref_value not in cookies:
        cookies[pref_value] = 0
      cookies[pref_value] += 1
    if 'browser.search.defaultenginename' == p:
      if pref_value not in search:
        search[pref_value] = 0
      search[pref_value] += 1
  return differs_from_default

  
def process_one_user(data, sample_count):
  buf = data.partition('\t')
  if (len(buf) != 3):
    errors['baduser_nosplit'] += 1
    return
  uid = buf[0]
  user_data = buf[2]
  try:
    d = json.loads(user_data)
  except:
    errors['baduser'] += 1
    return
  events = d.get('events')
  if not events:
    errors['baduser_noevents'] += 1
    return
  errors['gooduser'] += 1
  num_passwords = -1
  num_sites = -1
  highest_reuse = 0
  prefs_seen = False
  password_seen = False
  security_prefs = {}
  # Data looks like this [3,"Login Table","Total Passwords","2",1355777798873],
  for e in events:
    # Custom event
    if e[0] != 3:
      continue
    if e[1] == 'Security Pref':
      pref_name = e[2]
      pref_value = e[3]
      ts = e[4]
      if not pref_name in security_prefs:
        security_prefs[pref_name] = []
      security_prefs[pref_name].append([ts, pref_value])
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
  if security_prefs:
    if process_security_prefs(security_prefs, uid):
      errors['not_default'] += 1
    errors['gooduser_prefs'] += 1
    pwd_enabled = security_prefs['signon.rememberSignons'][0][1]
  if password_seen:
    errors['gooduser_password'] += 1
    if not pwd_enabled:
      errors['accidental_user'] += 1
    assert num_passwords >= 0, "Didn't get num passwords: %s" % uid
    assert num_sites >= 0, "Didn't get num_sites: %s" % uid
    process_password_stats(num_passwords, num_sites, highest_reuse, pwd_enabled)

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
  f = open('num_days.csv', 'w')
  for i in range(len(num_days)):
    f.write('%d %d\n' % (i, num_days[i],))
  f.close()
  f = open('cookie_behavior.csv', 'w')
  for c in sorted(cookies, key=cookies.get):
    f.write('%s, %d\n' % (c, cookies[c],))
  f.close()

  print "sites", sites
  f = open('passwords_per_site.csv', 'w')
  arr = numpy.array(sites)
  means = arr.mean(axis=1)
  std = arr.std(axis=1)
  print means
  print std
  for i in range(len(means)):
    f.write("%f,%f\n" % (means[i], std[i]))
  f.close()

  for e in errors:
    print e, errors[e]


try:
  f = open(sys.argv[1], 'r')
except:
  sys.exit("Can't find file")
init_maps()
sample_count = 0
for l in f.readlines():
  process_one_user(l, sample_count)
  sample_count += 1
finish()
f.close()
