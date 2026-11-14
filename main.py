# scratchstore module second concept (formerly scratchclouddb)

import scratchstore
from scratchstore import events

db = scratchstore.add("test", "./test.json")
scratchstore.connection.setup(_id=1234567890, username="username", password="password")
scratchstore.connection.use(databases=[db])
scratchstore.start(verbose=False, automatic=True) # verbose returns logs and automatic automatically reconnects to scratch cloud servers on disconnect

@events.event
def on_set(type, database, key, value, username):
	if type == 1:
		print(f"{username} set {key} to {value} in {database}")
	elif type == 2:
		print(f"{username} deleted {key} in {database}")

@events.event
def on_get(type, database, key, username):
	if type == 1:
		print(f"{username} got {key} in {database}")
	elif type == 2:
		print(f"{username} got all keys in {database}")
	elif type == 3:
		print(f"{username} got all databases")