import os
import hmac
import hashlib

from flask import Flask, request
from datetime import datetime
from urllib.parse import urlencode

app = Flask(__name__)

# Required to use Flask sessions and the debug toolbar
app.secret_key = "ABC"


SLACK_SIGNING_SECRET = os.environ['QUEUE_SIGNING_SECRET']



@app.route('/', methods=['POST'])
def index():

    if validate_request(request):
        return "Hello"
    else:
        return "I don't know you."



def validate_request(request):
    """Validates that the request comes from Slack"""

    # request_body = stringify_body(request)
    request_body = urlencode(request.form)

    timestamp = request.headers['X-Slack-Request-Timestamp']

    # check for replay attack
    if timestamp_too_old(timestamp):
        return

    return secrets_match(timestamp, request_body, request.headers['X-Slack-Signature'])


def timestamp_too_old(timestamp):
    """Uses timestamp to check request for replay attack."""

    now = datetime.timestamp(datetime.now())

    print(now)
    print(timestamp)

    # check for replay attack
    if abs(now - int(timestamp)) > 5 * 60:
        print(f"Request sent at {timestamp} which is not in the last 5 minutes.")
        return True

    return False


def secrets_match(timestamp, request_body, slack_sig):
    """Constructs signing secrets to confirm the messages is sent by Slack"""

    sig_basestring = bytearray('v0:' + timestamp + ":" + request_body, 'utf-8')
    secret = bytearray(SLACK_SIGNING_SECRET, 'utf-8')
    sig_encoded = hmac.new(secret, 
                           sig_basestring, 
                            digestmod=hashlib.sha256).hexdigest()
    my_sig = 'v0=' + sig_encoded

    if hmac.compare_digest(my_sig, slack_sig):
        return True

    return False



if __name__ == "__main__":

    app.run(debug=True, 
            use_reloader=True,
            port=5000, 
            host='127.0.0.1')