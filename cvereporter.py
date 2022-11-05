import datetime
import json
import logging
import pathlib
import sys
from enum import Enum
from os.path import join

import requests
import yaml
from discord import Color, Embed


class time_type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"


class cvereport:
    def __init__(self):

        self.CIRCL_LU_URL = "https://cve.circl.lu/api/query"
        self.CVES_JSON_PATH = join(
            pathlib.Path(__file__).parent.absolute(), "output/record.json"
        )
        self.LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
        self.LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
        self.TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
        self.logger = logging.getLogger("cve-reporter")

        self.new_cves = []
        self.mod_cves = []

        # Load keywords from config file

        self.KEYWORDS_CONFIG_PATH = join(
            pathlib.Path(__file__).parent.absolute(), "config/config.yaml"
        )
        try:

            with open(self.KEYWORDS_CONFIG_PATH, "r") as yaml_file:
                keywords_config = yaml.safe_load(yaml_file)
                print(f"Loaded keywords: {keywords_config}")
                self.valid = keywords_config["ALL_VALID"]
                self.keywords_i = keywords_config["DESCRIPTION_KEYWORDS_I"]
                self.keywords = keywords_config["DESCRIPTION_KEYWORDS"]
                self.product_i = keywords_config["PRODUCT_KEYWORDS_I"]
                self.product = keywords_config["PRODUCT_KEYWORDS"]

        except Exception as e:
            logging.error(e)
            sys.exit(1)

    ################## LOAD CONFIGURATIONS ####################

    def load_lasttimes(self):
        # Load lasttimes from json file

        try:
            with open(self.CVES_JSON_PATH, "r") as json_file:
                cves_time = json.load(json_file)
                self.LAST_NEW_CVE = datetime.datetime.strptime(
                    cves_time["LAST_NEW_CVE"], self.TIME_FORMAT
                )
                self.LAST_MODIFIED_CVE = datetime.datetime.strptime(
                    cves_time["LAST_MODIFIED_CVE"], self.TIME_FORMAT
                )

        except Exception as e:  # If error, just keep the fault date (today - 1 day)
            logging.error(f"ERROR, using default last times.\n{e}")

        print(f"Last new cve: {self.LAST_NEW_CVE}")
        print(f"Last modified cve: {self.LAST_MODIFIED_CVE}")

    def update_new_cve(self, published_date):
        # ratelimited update 1 by 1
        try:
            with open(self.CVES_JSON_PATH, "w") as json_file:
                json.dump(
                    {
                        "LAST_NEW_CVE": published_date,
                        "LAST_MODIFIED_CVE": self.LAST_MODIFIED_CVE.strftime(
                            self.TIME_FORMAT
                        ),
                    },
                    json_file,
                )
        except Exception as e:
            logging.error(f"ERROR: {e}")

    def update_new_modified(self, modified_date):
        # ratelimited update 1 by 1
        try:
            with open(self.CVES_JSON_PATH, "w") as json_file:
                json.dump(
                    {
                        "LAST_NEW_CVE": self.LAST_NEW_CVE.strftime(self.TIME_FORMAT),
                        "LAST_MODIFIED_CVE": modified_date,
                    },
                    json_file,
                )
        except Exception as e:
            logging.error(f"ERROR: {e}")

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
            logging.error(f"ERROR: {e}")

    ################## SEARCH CVES ####################

    def request_cves(self, tt_filter: time_type) -> dict:
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

    def get_new_cves(self):
        # Get CVEs that are new#

        cves = self.request_cves(time_type.PUBLISHED)
        self.new_cves, self.LAST_NEW_CVE = self.filter_cves(
            cves["results"], self.LAST_NEW_CVE, time_type.PUBLISHED
        )

    def get_modified_cves(self) -> list:
        # Get CVEs that has been modified

        cves = self.request_cves(time_type.LAST_MODIFIED)
        self.mod_cves, self.LAST_MODIFIED_CVE = self.filter_cves(
            cves["results"], self.LAST_MODIFIED_CVE, time_type.LAST_MODIFIED
        )

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

        # return blank because basic vulner user has limited search hence removing exploit search function, but source code works
        return []

        # vulners_api_key = os.getenv("VULNERS_API_KEY")

        # if vulners_api_key:
        #     vulners_api = vulners.VulnersApi(api_key=vulners_api_key)
        #     cve_data = vulners_api.find_exploit_all(cve)
        #     return [v["vhref"] for v in cve_data]

        # else:
        #     print("VULNERS_API_KEY wasn't configured in the secrets!")

        # return []

    #################### GENERATE MESSAGES #########################

    def generate_new_cve_message(self, cve_data: dict) -> Embed:
        # Generate new CVE message for sending to slack

        nl = "\n"
        embed = Embed(
            title=f"🚨  *{cve_data['id']}*  🚨",
            description=cve_data["summary"]
            if len(cve_data["summary"]) < 400
            else cve_data["summary"][:400] + "...",
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
                name=f"🔓  *Vulnerable* (_limit to 6_)",
                value=f"{nl.join(cve_data['vulnerable_configuration'][:6])}",
                inline=False,
            )

        embed.add_field(
            name=f"More Information (_limit to 4_)",
            value=f"{nl.join(cve_data['references'][:4])}",
            inline=False,
        )

        return embed

    def generate_modified_cve_message(self, cve_data: dict) -> Embed:
        # Generate modified CVE message for sending to slack
        # description=f"*{cve_data['id']}*(_{cve_data['cvss']}_) was modified on {cve_data['last-modified'].split('T')[0]}",
        descript = ""
        if "cvss-vector" in cve_data and cve_data["cvss-vector"] != "None":
            descript = f"CVSS: {cve_data['cvss-vector']} "
        if "cwe" in cve_data and cve_data["cwe"] != "None":
            descript += f"CWE: {cve_data['cwe']}"

        embed = Embed(
            title=f"📣 *{cve_data['id']} Modified*",
            description=descript,
            timestamp=datetime.datetime.utcnow(),
            color=Color.gold(),
        )

        embed.add_field(
            name=f"📅  *Modified*", value=f"{cve_data['last-modified']}", inline=True
        )

        embed.add_field(
            name=f"🗣 *Summary*",
            value=cve_data["summary"]
            if len(cve_data["summary"]) < 400
            else cve_data["summary"][:400] + "...",
        )

        embed.set_footer(
            text=f"(First published on {cve_data['Published'].split('T')[0]})\n"
        )

        return embed

    def generate_public_expls_message(self, public_expls: list) -> str:
        # Given the list of public exploits, generate the message

        message = ""
        nl = "\n"

        if public_expls:
            message = f"{nl.join(public_expls[:10])}"

        return message
