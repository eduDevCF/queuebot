import os
import hmac
import hashlib

from flask import Flask, request, session, jsonify
from datetime import datetime
from urllib.parse import urlencode

app = Flask(__name__)

# Required to use Flask sessions and the debug toolbar
app.secret_key = "ABC"


SLACK_SIGNING_SECRET = os.environ['QUEUE_SIGNING_SECRET']

# need to add persistent storage
current_queue = []



@app.route('/', methods=['POST'])
def index():

    print("Current QUEUE: ")
    print(current_queue)

    if validate_request(request):
        # parse_request(request)
        user_id = request.form.get('user_id')
        current_queue.append(f"<@{user_id}>")

        response_text = f'<@{user_id}> has joined the queue.'
        queue_display = { 'text': stringify_queue(current_queue) }
        help_request = { 'text': request.form.get('text') }
        attachments_list = [ help_request, queue_display ]
        # response = { 'text': response_text,
        #              'attachments': [ queue_display ] }

        return jsonify(text=response_text,
                       attachments=attachments_list)

    else:
        return "I don't know you."


def stringify_queue(queue):

    item_str = ", ".join(queue)

    return f"QUEUE = [ {item_str} ]"



# def parse_request(request):
#     """Pulls out info from the request body"""

#     command = request.form.get('command') # should equal "/queue"
#     text = request.form.get('text') # will need further parsing
#     response_url = request.form.get('response_url') # use this after mvp
#     user_id = request.form.get('user_id') # get users.info, especially is_admin
#     team_id = request.form.get('team_id')
#     channel_id = request.form.get('channel_id')

#     if command == "/queue":
#         return parse_text(text, user_id)


# def parse_text(text, user_id):

#     keyword, content = text.split(' ', 1)

#     if keyword == "open":
#         # check user.info.is_admin (later version)
#         # set queue status to open


#         # post in channel "The queue is now open."

#     elif keyword == "close":
#         # check user.info.is_admin
#         # set queue status to close
#         # post in channel "The queue is closed."

#     elif keyword  == "help":
#         # echo help request in channel 
#         # as_user ideally, but that would require the use of chat.postMessage and user authentication

#     elif keyword == "remove":
#         # remove self from queue
#         # check user.info.is_admin to remove others
#         # post updated queue in channel

#     elif keyword  == "next":
#         # check user.info.is_admin
#         # posts help message ephemerally
#         # pops the first person in the queue
#         # post in channel "On my way <@user>"
#         # update queue and post in channel QUEUQ: []

#     elif keyword == "view":
#         # check user.info.is_admin
#         # get the following term, which should be a number/index
#         # display help request as ephemeral message.

#     else:






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