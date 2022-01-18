import ast
import json
from bson import json_util
from flask import Flask, jsonify
from client.codes.agent import Agent
import pymongo
from urllib.parse import parse_qs


def parse_query_params(query_string):
    """
        Function to parse the query parameter string.
        """
    # Parse the query param string
    query_params = dict(parse_qs(query_string))
    # Get the value from the list
    query_params = {k: v[0] for k, v in query_params.items()}
    return query_params

app = Flask(__name__)
app.secret_key = b'\xcc^\x91\xea\x17-\xd0W\x03\xa7\xf8J0\xac8\xc5'

# Database
client = pymongo.MongoClient("mongodb+srv://danasror:mongodbharelmoria@mydb.gcbp0.mongodb.net/myDB?retryWrites=true&w=majority")
db = client.myDB


@app.route("/registration", methods=['POST'])
def create_user():
    try:
        try:
            agent = Agent()
            agent.run()
            computer_name = agent.computer_name
            client_result = json.dumps(agent.result_dict, indent=4)
            #body = ast.literal_eval(json.dumps(request.get_json()))
            body = ast.literal_eval(json.dumps({"client_name": computer_name, "scan_result": client_result}))
        except:
            # Bad request as request body is not available
            # Add message for debugging purpose
            return "", 400

        record_created = db.users.insert(body)

        # Prepare the response
        if isinstance(record_created, list):
            # Return list of Id of the newly created item
            return jsonify([str(v) for v in record_created]), 201
        else:
            # Return Id of the newly created item
            return jsonify(str(record_created)), 201
    except:
        # Error while trying to create the resource
        # Add message for debugging purpose
        return "", 500


@app.route("/find", methods=['GET'])
def find():
    data = db.users.find()
    docs_list = list(data)
    print(docs_list)
    return json.dumps(docs_list, indent=4, default=json_util.default), 201


if __name__ == "__main__":
    app.run(debug=True)