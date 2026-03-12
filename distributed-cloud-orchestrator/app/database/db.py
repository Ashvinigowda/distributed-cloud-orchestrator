from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")

db = client["shard_orchestrator"]

uploads_collection = db["uploads"]
nodes_collection = db["nodes"]
shards_collection = db["shards"]
join_codes_collection = db["join_codes"]
keys_collection = db["keys"]