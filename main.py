import requests
import datetime
import pathlib
import json
import os
import yaml
import vulners
from os.path import join
from enum import Enum
from discord import Webhook, RateLimited, Embed, Color, HTTPException
import aiohttp, asyncio
from keep_alive import keep_alive
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import logging, sys

from cvereporter import cvereport

logger = logging.getLogger('cvereporter')
logger.setLevel(logging.ERROR)
handler = logging.FileHandler(filename='cve_reporter_discord.log',
                              encoding='utf-8',
                              mode='w')
handler.setFormatter(
    logging.Formatter('%(asctime)s:%(levelname)s:%(name)s: %(message)s'))
logger.addHandler(handler)

def load_keywords():
    ''' Load keywords from config file '''
    
    KEYWORDS_CONFIG_PATH = join(pathlib.Path(__file__).parent.absolute(), "config/config.yaml")
    try:

        with open(KEYWORDS_CONFIG_PATH, 'r') as yaml_file:
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
    ''' Send a message to the discord channel webhook '''

    discord_webhok_url = os.getenv('DISCORD_WEBHOOK_URL')

    if not discord_webhok_url:
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    await sendtoWebhook(WebHookURL=discord_webhok_url, content=message)


async def sendtoWebhook(WebHookURL: str, content: Embed):
    async with aiohttp.ClientSession() as session:

        try:
            webhook = Webhook.from_url(WebHookURL, session=session)
            await webhook.send(embed=content)
        except HTTPException:
            #dict=content.todict()
            
            os.system("kill 1")
        except RateLimited:
            os.system("kill 1")


#################### CHECKING for CVE #########################


async def itscheckintime():

    try:
        #Load configured keywords
        (
        ALL_VALID,
        DESCRIPTION_KEYWORDS,
        DESCRIPTION_KEYWORDS_I,
        PRODUCT_KEYWORDS,
        PRODUCT_KEYWORDS_I,
        ) = load_keywords()

        cve = cvereporter(ALL_VALID,
        DESCRIPTION_KEYWORDS,
        DESCRIPTION_KEYWORDS_I,
        PRODUCT_KEYWORDS,
        PRODUCT_KEYWORDS_I,)

        #Start loading time of last checked ones
        cve.load_lasttimes()

        #Find a publish new CVEs
        new_cves = cve.get_new_cves()

        new_cves_ids = [ncve['id'] for ncve in new_cves]
        print(f"New CVEs discovered: {new_cves_ids}")

        for new_cve in new_cves:
            public_exploits = search_exploits(new_cve['id'])
            cve_message = generate_new_cve_message(new_cve)
            public_expls_msg = generate_public_expls_message(public_exploits)
            await send_discord_message(cve_message, public_expls_msg)

        #Find and publish modified CVEs
        modified_cves = get_modified_cves()

        modified_cves = [
            mcve for mcve in modified_cves if not mcve['id'] in new_cves_ids
        ]
        modified_cves_ids = [mcve['id'] for mcve in modified_cves]
        print(f"Modified CVEs discovered: {modified_cves_ids}")

        for modified_cve in modified_cves:
            public_exploits = search_exploits(modified_cve['id'])
            cve_message = generate_modified_cve_message(modified_cve)
            public_expls_msg = generate_public_expls_message(public_exploits)
            await send_discord_message(cve_message, public_expls_msg)

        #Update last times
        update_lasttimes()

    except Exception as e:
        logger.error(e)
        sys.exit(1)


#################### MAIN #########################
if __name__ == "__main__":
    scheduler = AsyncIOScheduler()
    scheduler.add_job(itscheckintime, 'interval', minutes=5)
    scheduler.start()
    print('Press Ctrl+{0} to exit'.format('Break' if os.name == 'nt' else 'C'))

    # Execution will block here until Ctrl+C (Ctrl+Break on Windows) is pressed.
    try:
        keep_alive()
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
