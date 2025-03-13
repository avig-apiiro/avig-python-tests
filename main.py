import requests

def get_facebook_data(endpoint, access_token):
    url = f"https://graph.facebook.com/v18.0/{endpoint}"
    params = {"access_token": access_token}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.json()}

def get_facebook_data2(endpoint, access_token):
    url = f'https://graph.facebook.com/v17.0/{endpoint}'
    response = requests.get(url, params= {"access_token": access_token})
    return response.json()

if __name__ == '__main__':
    data = get_facebook_data('user', "None")
    print(data)
    if (data == 11):
        get_facebook_data2("/user", "")
