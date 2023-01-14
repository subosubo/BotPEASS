All credits goes to carlospolop

Description (According to ChatGPT, Kudos)
This script is used to gather information about security vulnerabilities, and send that information to a specified Discord channel through a webhook. The script uses the cvereporter library to gather information about the vulnerabilities and the dotenv library to load environment variables from a .env file, including the webhook URL. The script also uses the json library to load and store data about security vulnerabilities in a JSON file, so that the script can continue from where it left off in the event of an interruption. The script also uses the apscheduler library to schedule the message sending and the aiohttp library to send the messages asynchronously, which allows for efficient and non-blocking execution of the script.

The script also uses logging for debugging purpose and storing it in a log file, which allows for easy identification and troubleshooting of any issues that may arise during the script's execution. The script is also using the asyncio library to schedule and send messages through a Discord webhook and embed message for sending the message in a more structured way.
