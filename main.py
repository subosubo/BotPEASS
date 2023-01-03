import asyncio
import logging
import os
import sys
from time import sleep
from pathlib import Path


from os.path import join, dirname
from dotenv import load_dotenv
import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from cvereporter import cvereport
from discord import Embed, HTTPException, Webhook
import pathlib
import json


dotenv_path = join(dirname(__file__), ".env")
load_dotenv(dotenv_path)

max_publish = 3

#################### LOG CONFIG #########################

# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create console handler and set level to debug
consolelog = logging.StreamHandler()
consolelog.setLevel(logging.INFO)

# create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s')

# add formatter to ch
consolelog.setFormatter(formatter)

# create file handler and set level to warning
log_dir = Path(__file__).parent.absolute()
log_dir.mkdir(parents=True, exist_ok=True)
filelog = logging.FileHandler(
    log_dir / 'cve_reporter_logfile.log', "a", "utf-8")
filelog.setLevel(logging.WARNING)

# create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to fh
filelog.setFormatter(formatter)

# add ch and fh to logger
logger.addHandler(consolelog)
logger.addHandler(filelog)

#################### LOAD CVE FROM JSON #########################

CVES_JSON_PATH = join(pathlib.Path(
    __file__).parent.absolute(), "output/cves.json")
MOD_CVES_JSON_PATH = join(
    pathlib.Path(__file__).parent.absolute(), "output/modcves.json"
)


def load_cves_to_publish():
    try:
        with open(CVES_JSON_PATH) as fp:
            listcve = json.load(fp)
        with open(MOD_CVES_JSON_PATH) as fp:
            listmodcve = json.load(fp)
        fp.close()
        return listcve, listmodcve
    except Exception as e:
        logger.error(f"ERROR_LOAD:{e}")


def store_cve_for_later(listcve, listmodcve):
    try:
        with open(CVES_JSON_PATH, "w") as json_file:
            json.dump(listcve, json_file, indent=4, separators=(",", ": "))
        with open(MOD_CVES_JSON_PATH, "w") as json_file:
            json.dump(listmodcve, json_file, indent=4, separators=(",", ": "))
        json_file.close()
    except Exception as e:
        logger.error(f"ERROR_STORE:{e}")


#################### SEND MESSAGES #########################


async def send_discord_message(
    message: Embed, public_expls_msg: str
):
    # Send a message to the discord channel webhook

    discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    if not discord_webhook_url:
        logger.error("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    if public_expls_msg:
        message = message.add_field(
            name=f"😈  *Public Exploits* (_limit 10_)  😈", value=public_expls_msg
        )

    await sendtowebhook(
        webhookurl=discord_webhook_url,
        content=message
    )


async def send_discord_message(
    message: Embed
):
    # Send a message to the discord channel webhook

    discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    if not discord_webhook_url:
        logger.error("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    await sendtowebhook(
        webhookurl=discord_webhook_url,
        content=message
    )


async def sendtowebhook(webhookurl: str, content: Embed):
    async with aiohttp.ClientSession() as session:

        try:
            webhook = Webhook.from_url(webhookurl, session=session)
            await webhook.send(embed=content)

        except HTTPException as e:
            logger.error(f"ERROR_SEND_HTTP: {e}")
            sleep(180)
            await webhook.send(embed=content)


#################### CHECKING for CVE #########################


async def itscheckintime():

    try:
        list_to_pub, mod_list_to_pub = load_cves_to_publish()

        # new class obj cvereport
        cve = cvereport()

        # Start loading time of last checked ones
        cve.load_lasttimes()

        # Find a publish new CVEs
        cve.get_new_cves()
        cve.get_modified_cves()

        # Update last times
        cve.update_lasttimes()

        list_to_pub.extend(cve.new_cves)
        mod_list_to_pub.extend(cve.mod_cves)

        if list_to_pub:
            for new_cve in list_to_pub[:max_publish]:
                cve_message = cve.generate_new_cve_message(new_cve)
                await send_discord_message(cve_message)

        if mod_list_to_pub:
            for modified_cve in mod_list_to_pub[:max_publish]:
                cve_message = cve.generate_modified_cve_message(modified_cve)
                await send_discord_message(cve_message)

        store_cve_for_later(
            list_to_pub[max_publish:], mod_list_to_pub[max_publish:])

    except Exception as e:
        logger.error(f"ERROR-1:{e}")
        sys.exit(1)


#################### MAIN #########################

if __name__ == "__main__":
    scheduler = AsyncIOScheduler(timezone="Asia/Singapore")
    scheduler.add_job(
        itscheckintime, "cron", day_of_week="mon-fri", hour="8-18", minute="*/3"
    )  # only weekdays, singapore time zone, from 8am - 6.48pm
    scheduler.start()

    logger.info(
        "Press Ctrl+{0} to exit".format("Break" if os.name == "nt" else "C"))

    # Execution will block here until Ctrl+C (Ctrl+Break on Windows) is pressed.
    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit) as e:
        logger.warning(e)
        raise
