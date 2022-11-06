import asyncio
import logging
import os
import sys

import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from discord import Embed, HTTPException, RateLimited, Webhook

from cvereporter import cvereport, time_type
from keep_alive import keep_alive

#################### LOG CONFIG #########################

log = logging.getLogger("cve-reporter")
log.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",
                              "%Y-%m-%d %H:%M:%S")

# Log to file
filehandler = logging.FileHandler("cve_reporter_discord.log", "w", "utf-8")
filehandler.setLevel(logging.DEBUG)
filehandler.setFormatter(formatter)
log.addHandler(filehandler)

# Log to stdout too
streamhandler = logging.StreamHandler()
streamhandler.setLevel(logging.INFO)
streamhandler.setFormatter(formatter)
log.addHandler(streamhandler)


#################### SEND MESSAGES #########################
async def send_discord_message(message: Embed, public_expls_msg: str,
                               tt_filter: time_type, cve: cvereport):
    # Send a message to the discord channel webhook

    discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    if not discord_webhook_url:
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    if public_expls_msg:
        message = message.add_field(
            name=f"😈  *Public Exploits* (_limit 10_)  😈",
            value=public_expls_msg)

    await sendtowebhook(
        webhookurl=discord_webhook_url,
        content=message,
        category=tt_filter.value,
        cve=cve,
    )


async def sendtowebhook(webhookurl: str, content: Embed, category: str,
                        cve: cvereport):
    async with aiohttp.ClientSession() as session:

        try:
            webhook = Webhook.from_url(webhookurl, session=session)
            await webhook.send(embed=content)
        except RateLimited(600.0):
            logging.debug("ratelimited error")
            os.system("kill 1")
        except HTTPException(status=429):
            logging.debug("http error")
            os.system("kill 1")
            # if category == "Published":
            #     date = content.to_dict()["fields"][2]["value"]
            #     cve.update_new_cve(date)

            # elif category == "last-modified":
            #     date = content.to_dict()["fields"][2]["value"]
            #     cve.update_new_modified(date)


#################### CHECKING for CVE #########################


async def itscheckintime():

    try:

        cve = cvereport()

        # Start loading time of last checked ones
        cve.load_lasttimes()

        # Find a publish new CVEs
        cve.get_new_cves()

        new_cves_ids = [ncve["id"] for ncve in cve.new_cves]
        print(f"New CVEs discovered: {new_cves_ids}")

        for new_cve in cve.new_cves:
            public_exploits = cve.search_exploits(new_cve["id"])
            cve_message = cve.generate_new_cve_message(new_cve)
            public_expls_msg = cve.generate_public_expls_message(
                public_exploits)
            await send_discord_message(cve_message, public_expls_msg,
                                       time_type.PUBLISHED, cve)

        # Find and publish modified CVEs
        cve.get_modified_cves()

        modified_cves = [
            mcve for mcve in cve.mod_cves if mcve["id"] not in new_cves_ids
        ]
        modified_cves_ids = [mcve["id"] for mcve in modified_cves]
        print(f"Modified CVEs discovered: {modified_cves_ids}")

        for modified_cve in modified_cves:
            public_exploits = cve.search_exploits(modified_cve["id"])
            cve_message = cve.generate_modified_cve_message(modified_cve)
            public_expls_msg = cve.generate_public_expls_message(
                public_exploits)
            await send_discord_message(cve_message, public_expls_msg,
                                       time_type.LAST_MODIFIED, cve)

        # Update last times
        cve.update_lasttimes()

    except Exception as e:
        logging.error(e)
        sys.exit(1)


#################### MAIN #########################

if __name__ == "__main__":
    scheduler = AsyncIOScheduler()
    scheduler.add_job(itscheckintime, "interval", minutes=5)
    scheduler.start()
    print("Press Ctrl+{0} to exit".format("Break" if os.name == "nt" else "C"))

    # Execution will block here until Ctrl+C (Ctrl+Break on Windows) is pressed.
    try:
        keep_alive()
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit) as e:
        logging.error(e)
        raise
