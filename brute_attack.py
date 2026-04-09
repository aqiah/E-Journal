import requests

url = "http://127.0.0.1:5000/login"
# This script simulates a bot trying 10 rapid guesses
for i in range(1, 11):
    # We send random passwords to see if the server blocks us
    data = {'username': 'haiqs', 'password': f'guess_{i}'}
    response = requests.post(url, data=data)
    print(f"Attempt {i}: Received Status {response.status_code}")