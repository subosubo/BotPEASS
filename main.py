import asyncio
import logging
import os
import sys
from time import sleep

from os.path import join, dirname
from dotenv import load_dotenv
import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from cvereporter import cvereport, time_type
from discord import Embed, HTTPException, Webhook
import pathlib
import json


dotenv_path = join(dirname(__file__), ".env")
load_dotenv(dotenv_path)

max_publish = 3

#################### LOG CONFIG #########################

# Create a custom logger
logger = logging.getLogger(__name__)

# Create handlers
c_handler = logging.StreamHandler()
f_handler = logging.FileHandler("cve_reporter_discord.log", "a", "utf-8")
c_handler.setLevel(logging.WARNING)
f_handler.setLevel(logging.ERROR)

# Create formatters and add it to handlers
c_format = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
f_format = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)

# Add handlers to the logger
logger.addHandler(c_handler)
logger.addHandler(f_handler)

#################### LOAD CVE FROM JSON #########################

CVES_JSON_PATH = join(pathlib.Path(
    __file__).parent.absolute(), "output/cves.json")
MOD_CVES_JSON_PATH = join(
    pathlib.Path(__file__).parent.absolute(), "output/modcves.json"
)


def load_cves_to_publish():
    try:
        listcve = []
        listmodcve = []
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
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
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
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
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
        list_to_pub = []
        mod_list_to_pub = []

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

        for new_cve in cve.new_cves:
            list_to_pub.append(new_cve)

        for modified_cve in cve.mod_cves:
            mod_list_to_pub.append(modified_cve)

        if list_to_pub:
            for new_cve in list_to_pub[:max_publish]:
                cve_message = cve.generate_new_cve_message(new_cve)
                await send_discord_message(cve_message)

        if mod_list_to_pub:
            for modified_cve in mod_list_to_pub[:max_publish]:
                print(f"{modified_cve}")
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
        itscheckintime, "cron", day_of_week="mon-fri", hour="8-18", minute="*/5"
    )  # only weekdays, 7am - 7pm, every 5 mins interval
    scheduler.start()

    print("Press Ctrl+{0} to exit".format("Break" if os.name == "nt" else "C"))

    # Execution will block here until Ctrl+C (Ctrl+Break on Windows) is pressed.
    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit) as e:
        logger.warning(e)
        raise
