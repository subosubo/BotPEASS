from threading import Thread
from flask import Flask

app = Flask(__name__)

@app.route('/', methods = ['HEAD','GET'])
async def home():
    return 'Stayin Alive'

def run():
    app.run(host = "0.0.0.0", port=5000)

def keep_alive():
    t = Thread(target=run)
    t.start()