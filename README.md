[![Go Report Card](https://goreportcard.com/badge/github.com/Luzifer/rss-status)](https://goreportcard.com/report/github.com/Luzifer/rss-status)
![](https://badges.fyi/github/license/Luzifer/rss-status)
![](https://badges.fyi/github/downloads/Luzifer/rss-status)
![](https://badges.fyi/github/latest-release/Luzifer/rss-status)

# Luzifer / rss-status

`rss-status` is a read-only bridge between RSS feeds and Mastodon / OStatus applications. The intention behind is for example to subscribe to Github-Status, LatestVer or other feeds with short content (sure, blog feeds do work but they contain too much text to be usefully subscribed into a Mastodon instance) using a Mastodon account.

In order to keep the list of feeds under control currently there is no possibility to modify the list of feeds from the users side: All feeds and corresponding "account names" are defined in the `feeds.yml` file by the administrator of the bridge.
