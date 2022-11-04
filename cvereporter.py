import datetime
import json
import os
import pathlib
from enum import Enum
from os.path import join

import requests
import vulners
from discord import Color, Embed


class time_type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"


class cvereport:
    def __init__(self, valid, keywords, keywords_i, product, product_i):
        self.valid = valid
        self.keywords = keywords
        self.keywords_i = keywords_i
        self.product = product
        self.product_i = product_i

        self.CIRCL_LU_URL = "https://cve.circl.lu/api/query"
        self.CVES_JSON_PATH = join(
            pathlib.Path(__file__).parent.absolute(), "output/record.json"
        )
        self.LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
        self.LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
        self.TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

    ################## LOAD CONFIGURATIONS ####################

    def load_lasttimes(self):
        # Load lasttimes from json file

        try:
            with open(self.CVES_JSON_PATH, "r") as json_file:
                cves_time = json.load(json_file)
                LAST_NEW_CVE = datetime.datetime.strptime(
                    cves_time["LAST_NEW_CVE"], self.TIME_FORMAT
                )
                LAST_MODIFIED_CVE = datetime.datetime.strptime(
                    cves_time["LAST_MODIFIED_CVE"], self.TIME_FORMAT
                )

        except Exception as e:  # If error, just keep the fault date (today - 1 day)
            print(f"ERROR, using default last times.\n{e}")

        print(f"Last new cve: {LAST_NEW_CVE}")
        print(f"Last modified cve: {LAST_MODIFIED_CVE}")

    def update_lasttimes(self):
        # Save lasttimes in json file
        try:
            with open(self.CVES_JSON_PATH, "w") as json_file:
                json.dump(
                    {
                        "LAST_NEW_CVE": self.LAST_NEW_CVE.strftime(self.TIME_FORMAT),
                        "LAST_MODIFIED_CVE": self.LAST_MODIFIED_CVE.strftime(
                            self.TIME_FORMAT
                        ),
                    },
                    json_file,
                )
        except Exception as e:
            print(f"ERROR: {e}")

    ################## SEARCH CVES ####################

    def get_cves(self, tt_filter: time_type) -> dict:
        # Given the headers for the API retrive CVEs from cve.circl.lu
        now = datetime.datetime.now() - datetime.timedelta(days=1)
        now_str = now.strftime("%d-%m-%Y")
        # https://cve.circl.lu/api/
        # time_modifier	Timeframe for the CVEs, related to the start and end time
        # time_start	Earliest time for a CVE
        # time_type	Select which time is used for the filter
        # limit	Limit the amount of vulnerabilities to return

        headers = {
            "time_modifier": "from",
            "time_start": now_str,
            "time_type": tt_filter.value,
            "limit": "100",
        }
        r = requests.get(self.CIRCL_LU_URL, headers=headers)

        return r.json()

    def get_new_cves(self) -> list:
        # Get CVEs that are new#

        cves = self.get_cves(time_type.PUBLISHED)
        filtered_cves, new_last_time = self.filter_cves(
            cves["results"], self.LAST_NEW_CVE, time_type.PUBLISHED
        )
        self.LAST_NEW_CVE = new_last_time

        return filtered_cves

    def get_modified_cves(self) -> list:
        # Get CVEs that has been modified

        cves = self.get_cves(time_type.LAST_MODIFIED)
        filtered_cves, new_last_time = self.filter_cves(
            cves["results"], self.LAST_MODIFIED_CVE, time_type.LAST_MODIFIED
        )
        self.LAST_MODIFIED_CVE = new_last_time

        return filtered_cves

    def filter_cves(
        self, cves: list, last_time: datetime.datetime, tt_filter: time_type
    ):
        # Filter by time the given list of CVEs

        filtered_cves = []
        new_last_time = last_time

        for cve in cves:
            cve_time = datetime.datetime.strptime(
                cve[tt_filter.value], self.TIME_FORMAT
            )
            # last_time is from config
            # cve time is api data
            # caters to multiple new cves with same published/modified time
            if cve_time > last_time:
                if (
                    self.valid
                    or self.is_summ_keyword_present(cve["summary"])
                    or self.is_prod_keyword_present(
                        str(cve["vulnerable_configuration"])
                    )
                ):

                    filtered_cves.append(cve)

            if cve_time > new_last_time:
                new_last_time = cve_time

        return filtered_cves, new_last_time

    def is_summ_keyword_present(self, summary: str):
        # Given the summary check if any keyword is present

        return any(w in summary for w in self.keywords) or any(
            w.lower() in summary.lower() for w in self.keywords_i
        )  # for each of the word in description keyword config, check if it exists in summary.

    def is_prod_keyword_present(self, products: str):
        # Given the summary check if any keyword is present

        return any(w in products for w in self.product) or any(
            w.lower() in products.lower() for w in self.product_i
        )

    def search_exploits(self, cve: str) -> list:
        # Given a CVE it will search for public exploits to abuse it
        # use bot commands to find exploits for particular CVE

        vulners_api_key = os.getenv("VULNERS_API_KEY")

        if vulners_api_key:
            vulners_api = vulners.Vulners(api_key=vulners_api_key)
            cve_data = vulners_api.searchExploit(cve)
            return [v["vhref"] for v in cve_data]

        else:
            print("VULNERS_API_KEY wasn't configured in the secrets!")

        return []

    #################### GENERATE MESSAGES #########################

    def generate_new_cve_message(self, cve_data: dict) -> Embed:
        # Generate new CVE message for sending to slack

        nl = "\n"
        embed = Embed(
            title=f"🚨  *{cve_data['id']}*  🚨",
            description=cve_data["summary"]
            if len(cve_data["summary"]) < 500
            else cve_data["summary"][:500] + "...",
            timestamp=datetime.datetime.utcnow(),
            color=Color.blue(),
        )

        if cve_data["cvss"] != "None":
            embed.add_field(name=f"🔮  *CVSS*", value=f"{cve_data['cvss']}", inline=True)

        embed.add_field(
            name=f"📅  *Published*", value=f"{cve_data['Published']}", inline=True
        )

        if cve_data["vulnerable_configuration"]:
            embed.add_field(
                name=f"\n🔓  *Vulnerable* (_limit to 10_)",
                value=f"{cve_data['vulnerable_configuration'][:10]}",
            )

        embed.add_field(
            name=f"More Information (_limit to 5_)",
            value=f"{nl.join(cve_data['references'][:5])}",
            inline=False,
        )

        return embed

    def generate_modified_cve_message(self, cve_data: dict) -> Embed:
        # Generate modified CVE message for sending to slack

        embed = Embed(
            title=f"📣 *{cve_data['id']} Modified*",
            description=f"*{cve_data['id']}*(_{cve_data['cvss']}_) was modified on {cve_data['last-modified'].split('T')[0]}",
            timestamp=datetime.datetime.utcnow(),
            color=Color.gold(),
        )

        embed.add_field(
            name=f"🗣 *Summary*",
            value=cve_data["summary"]
            if len(cve_data["summary"]) < 500
            else cve_data["summary"][:500] + "...",
            inline=False,
        )

        # if key exists and there is a value
        if "cvss-vector" in cve_data and cve_data["cvss-vector"] != "None":
            embed.add_field(
                name=f"🔮  *CVSS*", value=f"{cve_data['cvss-vector']}", inline=True
            )

        if "cwe" in cve_data and cve_data["cwe"] != "None":
            embed.add_field(name=f"✏️  *CWE*", value=f"{cve_data['cwe']}", inline=True)

        embed.set_footer(
            text=f"(First published on {cve_data['Published'].split('T')[0]})\n"
        )

        return embed

    def generate_public_expls_message(self, public_expls: list) -> Embed:
        # Given the list of public exploits, generate the message

        embed = Embed(
            title=f"**Public Exploits located**",
            timestamp=datetime.datetime.utcnow(),
            color=Color.red(),
        )
        embed.add_field(
            name=f"More Information (_limit to 20_)",
            value=f"{public_expls[:20]}",
            inline=False,
        )
        return embed
