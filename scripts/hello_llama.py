import os
from ollama import Client

client = Client(host=os.environ.get('OLLAMA_HOST', 'http://192.168.56.1:11434'))

response = client.generate(
    model='llama3.2',
    prompt='In one sentence, what is a phishing email?'
)
print(response['response'])
