All credits goes to carlospolop

Keys Points here
1. Loads Keywords from Json
2. Track Hits from CVE database with time filter
3. Search for exploits on Vulner
4. Report New and Modified CVE Results on Discord via Discord Webhook
5. Update time filter
6. Runs on Async scheduler calling every 5 mins
7. Kept alive on Replit IDE with UptimeRobot - https://www.youtube.com/watch?v=SPTfmiYiuok

**Dependencies**
python = "^3.8"
vulners = "^2.0.2"
discord = "^2.0.0"
requests = "^2.28.1"
Flask = "^2.2.2"
feedparser = "^6.0.10"
aiohttp = "^3.8.1"
waitress = "^2.1.2"
schedule = "^1.1.0"
APScheduler = "^3.9.1"
nest-asyncio = "^1.5.5"
