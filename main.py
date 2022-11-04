import asyncio
import logging
import os
import pathlib
import sys
from os.path import join

import aiohttp
import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from discord import Embed, HTTPException, RateLimited, Webhook

from cvereporter import cvereport
from keep_alive import keep_alive

logger = logging.getLogger("cvereporter")
logging.basicConfig(
    handlers=[
        logging.FileHandler(
            filename="cve_reporter_discord.log", encoding="utf-8", mode="w"
        )
    ],
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)


def load_keywords():
    # Load keywords from config file

    KEYWORDS_CONFIG_PATH = join(
        pathlib.Path(__file__).parent.absolute(), "config/config.yaml"
    )
    try:

        with open(KEYWORDS_CONFIG_PATH, "r") as yaml_file:
            keywords_config = yaml.safe_load(yaml_file)
            print(f"Loaded keywords: {keywords_config}")
            ALL_VALID = keywords_config["ALL_VALID"]
            DESCRIPTION_KEYWORDS_I = keywords_config["DESCRIPTION_KEYWORDS_I"]
            DESCRIPTION_KEYWORDS = keywords_config["DESCRIPTION_KEYWORDS"]
            PRODUCT_KEYWORDS_I = keywords_config["PRODUCT_KEYWORDS_I"]
            PRODUCT_KEYWORDS = keywords_config["PRODUCT_KEYWORDS"]

            return (
                ALL_VALID,
                DESCRIPTION_KEYWORDS,
                DESCRIPTION_KEYWORDS_I,
                PRODUCT_KEYWORDS,
                PRODUCT_KEYWORDS_I,
            )

    except Exception as e:
        logger.error(e)
        sys.exit(1)


#################### SEND MESSAGES #########################


async def send_discord_message(message: Embed, public_expls_msg: str):
    # Send a message to the discord channel webhook

    discord_webhok_url = os.getenv("DISCORD_WEBHOOK_URL")

    if not discord_webhok_url:
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    if public_expls_msg:
        message = message.add_field(
            name=f"😈  *Public Exploits* (_limit 10_)  😈", value=public_expls_msg
        )

    await sendtowebhook(webhookurl=discord_webhok_url, content=message)


async def sendtowebhook(webhookurl: str, content: Embed):
    async with aiohttp.ClientSession() as session:

        try:
            webhook = Webhook.from_url(webhookurl, session=session)
            await webhook.send(embed=content)
        except (RateLimited):
            content_dict = content.todict()
            print(f"{content_dict}")
            logger.error(f"Ratelimit Error")
            raise
        except HTTPException:
            logger.error(f"HTTPException")
            raise
            # os.system("kill 1")


#################### CHECKING for CVE #########################


async def itscheckintime():

    try:
        # Load configured keywords
        (
            ALL_VALID,
            DESCRIPTION_KEYWORDS,
            DESCRIPTION_KEYWORDS_I,
            PRODUCT_KEYWORDS,
            PRODUCT_KEYWORDS_I,
        ) = load_keywords()

        cve = cvereport(
            ALL_VALID,
            DESCRIPTION_KEYWORDS,
            DESCRIPTION_KEYWORDS_I,
            PRODUCT_KEYWORDS,
            PRODUCT_KEYWORDS_I,
        )

        # Start loading time of last checked ones
        cve.load_lasttimes()

        # Find a publish new CVEs
        new_cves = cve.get_new_cves()

        new_cves_ids = [ncve["id"] for ncve in new_cves]
        print(f"New CVEs discovered: {new_cves_ids}")

        for new_cve in new_cves:
            public_exploits = cve.search_exploits(new_cve["id"])
            cve_message = cve.generate_new_cve_message(new_cve)
            public_expls_msg = cve.generate_public_expls_message(public_exploits)
            await send_discord_message(cve_message, public_expls_msg)

        # Find and publish modified CVEs
        modified_cves = cve.get_modified_cves()

        modified_cves = [
            mcve for mcve in modified_cves if mcve["id"] not in new_cves_ids
        ]
        modified_cves_ids = [mcve["id"] for mcve in modified_cves]
        print(f"Modified CVEs discovered: {modified_cves_ids}")

        for modified_cve in modified_cves:
            public_exploits = cve.search_exploits(modified_cve["id"])
            cve_message = cve.generate_modified_cve_message(modified_cve)
            public_expls_msg = cve.generate_public_expls_message(public_exploits)
            await send_discord_message(cve_message, public_expls_msg)

        # Update last times
        cve.update_lasttimes()

    except Exception as e:
        logger.error(e)
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
        logger.error(e)
        raise
