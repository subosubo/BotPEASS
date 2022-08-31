from threading import Thread
from flask import Flask, request
import botpeas

app = Flask('')

@app.route('/', methods = ['HEAD','GET'])
def home():
    if request.method == 'HEAD':
        botpeas.main()
        
    return 'Stayin Alive'

def run():
    app.run(host = '0.0.0.0', port=8080)

def main():
    t = Thread(target = run)
    t.start()

if __name__ == "__main__":
    main()