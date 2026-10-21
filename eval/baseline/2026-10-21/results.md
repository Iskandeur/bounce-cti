# Bounce-CTI against the same model without it


## Recall on the fresh subset (same scorer, same ground truth)

REC here is ungated: mean of NR, COV, ER and MK whether or not the live data has decayed, so the three sides are averaged over the same dimensions.

| Case | Side | NR | ER | MK | COV | REC | Actor named | Attributions | Untraceable | Tool calls |
|---|---|---:|---:|---:|---:|---:|:---:|---:|---:|---:|
| 2 | Bounce-CTI | 63.6 | 33.3 | 100 | 63.6 | 65.1 | yes | 0 | 0 | 71 |
| 2 | bare model + web | 100.0 | 33.3 | 100 | 100.0 | 83.3 | yes | 5 | 0 | 29 |
| 2 | bare model, memory only | 9.1 | 0.0 | 0 | 9.1 | 4.5 | no | 0 | 0 | 0 |
| 3 | Bounce-CTI | 47.1 | 66.7 | 100 | 52.9 | 66.7 | yes | 0 | 0 | 55 |
| 3 | bare model + web | 94.1 | 66.7 | 100 | 100.0 | 90.2 | yes | 5 | 0 | 27 |
| 3 | bare model, memory only | 5.9 | 0.0 | 0 | 5.9 | 2.9 | no | 0 | 0 | 0 |
| 8 | Bounce-CTI | 50.0 | 33.3 | 100 | 50.0 | 58.3 | yes | 0 | 0 | 63 |
| 8 | bare model + web | 50.0 | 33.3 | 100 | 50.0 | 58.3 | yes | 6 | 0 | 43 |
| 8 | bare model, memory only | 12.5 | 0.0 | 0 | 12.5 | 6.2 | no | 0 | 0 | 0 |
| 9 | Bounce-CTI | 66.7 | 100.0 | 100 | 66.7 | 83.3 | yes | 1 | 0 | 62 |
| 9 | bare model + web | 83.3 | 100.0 | 100 | 83.3 | 91.7 | yes | 2 | 0 | 21 |
| 9 | bare model, memory only | 33.3 | 0.0 | 0 | 33.3 | 16.7 | no | 0 | 0 | 0 |
| 12 | Bounce-CTI | 50.0 | 0.0 | 100 | 66.7 | 54.2 | yes | 0 | 0 | 51 |
| 12 | bare model + web | 87.5 | 0.0 | 100 | 100.0 | 71.9 | yes | 4 | 0 | 30 |
| 12 | bare model, memory only | 12.5 | 0.0 | 100 | 33.3 | 36.5 | no | 0 | 0 | 0 |

| Side | NR mean | REC mean | Cases with the actor named | Untraceable attributions |
|---|---:|---:|---:|---:|
| Bounce-CTI | 55.5 | 65.5 | 5/5 | 0 |
| bare model + web | 83.0 | 79.1 | 5/5 | 0 |
| bare model, memory only | 14.7 | 13.4 | 0/5 | 0 |

## Restraint on benign seeds (RST: 100 = no cluster, no attribution)

| Case | Bounce-CTI | bare model + web | bare model, memory only |
|---|---:|---:|---:|
| N1 | 100 | 100 | 100 |
| N2 | 0 | 0 | 100 |
| N3 | 100 | 100 | 100 |

## What the web arm read

The ground truth comes from public write-ups (`cases.GT_SOURCE_HOSTS`). "Answer key" says whether the web arm fetched that write-up, met it in a search result's snippet, or did not reach it.

- **2** (answer key: **fetched**): fetched bazaar.abuse.ch, cert.ug, ipinfo.io, malshare.com, muddy.vibecoded.systems, otx.alienvault.com, threatfox.abuse.ch, threatlabsnews.xcitium.com, tria.ge, urlscan.io, www.broadcom.com, www.filescan.io, www.hybrid-analysis.com, www.jumpsec.com, www.rapid7.com, www.virustotal.com; in search results also cyberscoop.com, daylight.ai, eckstein-shop.de, en.wikipedia.org, epics.anl.gov, es.digitaltrends.com, ftp.nmr.mgh.harvard.edu, infosecurity-magazine.com, lyrie.ai, medium.com, petri.com, socprime.com (+18 more in results.json)
- **3** (answer key: **fetched**): fetched bazaar.abuse.ch, cybersecuritynews.com, gbhackers.com, ipinfo.io, medium.com, rdap.db.ripe.net, thedfirreport.com, tria.ge, www.hendryadrian.com, www.hybrid-analysis.com, www.virustotal.com; in search results also bugzilla.mozilla.org, cyberpress.org, cyble.com, dev.to, dribbble.com, en.wikipedia.org, forums.anandtech.com, github.com, huggingface.co, learn.microsoft.com, lmntrix.com, malwaretips.com (+15 more in results.json)
- **8** (answer key: **not reached**): fetched any.run, bazaar.abuse.ch, otx.alienvault.com, stat.ripe.net, threatfox.abuse.ch, tria.ge, www.bitsight.com, www.filescan.io, www.hybrid-analysis.com, www.virustotal.com; in search results also archive.umsida.ac.id, cgit-dev.freebsd.org, en.wikipedia.org, epics.anl.gov, git.centos.org, huggingface.co, lda.senate.gov, redpiranha.net, socradar.io, www.ajou.ac.kr, www.cisco.com, www.joesandbox.com (+3 more in results.json)
- **9** (answer key: **not reached**): fetched otx.alienvault.com, pastebin.com, rdap.org, threatfox.abuse.ch, urlscan.io, www.cyfirma.com, www.microsoft.com, www.securefeed.com, www.virustotal.com, www.whois.com; in search results also blog.sekoia.io, cybersecuritynews.com, en.wikipedia.org, gridinsoft.com, lei.bloomberg.com, phishdestroy.io, spycloud.com, www.dataproof.co.za, www.esentire.com, www.malwarebytes.com, www.pointwild.com, www.proofpoint.com (+2 more in results.json)
- **12** (answer key: **fetched**): fetched api.bgpview.io, api.github.com, api.hackertarget.com, blog.sekoia.io, canon.whisper.security, crt.sh, duckduckgo.com, guard.io, html.duckduckgo.com, labs.guard.io, otx.alienvault.com, raw.githubusercontent.com, search.marcia.dev, threatfox.abuse.ch, urlscan.io, www.google.com, www.sekoia.com, www.virustotal.com; in search results also builtwith.com, datapedia.shodan.io, docs.cloud.google.com, en.wikipedia.org, gist.github.com, github.com, gopivot.ing, kmsec.uk, patents.google.com, patents.justia.com, patentsgazette.uspto.gov, www.coursera.org (+4 more in results.json)
- **N1**: fetched api.bgpview.io, ipinfo.io, ismalicious.com, pulsedive.com, rdap.arin.net, www.abuseipdb.com, www.cloudflare.com; in search results also academic.oup.com, en.wikipedia.org, jamesbrine.com.au, precisionsec.com, robtex.com, webdivo.com, www.cisecurity.org, www.malwarepatrol.net, www.netify.ai, www.silentpush.com
- **N2**: fetched ams.report-uri.com, dns.google, report-uri.com, urlscan.io, www.jsdelivr.com; in search results also anyrun.substack.com, awesome.ecosyste.ms, blog.checkpoint.com, blog.malwarebytes.com, cdnalliance.org, cop.evidon.com, directory.cside.com, en.wikipedia.org, gcore.com, gist.github.com, github.com, gurucul.com (+19 more in results.json)
- **N3**: fetched api.certspotter.com, crt.sh, dns.google, rdap.db.ripe.net, rdap.publicinterestregistry.org, rdap.verisign.com, stat.ripe.net, urlscan.io; in search results also bgp.he.net, cert.imfht.com, feed.craftedsignal.io, ipv4.bgp.he.net, mitre.ptsecurity.com, redteam.y-security.de, rtsak.com, securelayer7.net, thehackernews.com, theipapi.com, www.cbinsights.com, www.netskope.com
