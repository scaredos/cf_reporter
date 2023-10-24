import requests
import time

from datetime import datetime, timedelta

# Variables
cloudflare_email = ''  # Account Email
api_token = ''  # Cloudflare API Key
zone_id = ''  # Domain Zone ID

abuseipdb_key = ''  # AbuseIPDB API Key


# Cloudflare GraphQL endpoint
url = 'https://api.cloudflare.com/client/v4/graphql'

historical_hours = 1


def get_past_date(num_hours: int) -> datetime.date:
    """
    Get past date given number of hours

    Parameters:
    num_hours (int): Number of hours to go back in time

    Returns:
    datetime.date : Time X amount of hours before
    """
    now = datetime.utcnow().date()
    return now - timedelta(hours=num_hours)


def get_cf_graphql(start_date: datetime.date, end_date: datetime.date) -> requests.request:
    """
    Get CF GraphQL Firewall Events

    Parameters:
    start_date (datetime.date): Start date to query firewall events
    end_date (datetime.date): End date to query firewall events

    Returns:
    requests.request: response from CF GraphQL endpoint
    """
    assert (start_date <= end_date)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_token}',
        'X-Auth-Email': cloudflare_email,
        'X-Auth-Key': api_token
    }
    # The GQL query we would like to use:
    payload = f'''{{"query":
      "query ListFirewallEvents($zoneTag: string) {{
        viewer {{
          zones(
            filter: {{ zoneTag: $zoneTag }}
          ) {{
            firewallEventsAdaptive(
              filter: $filter
              limit: 100
              orderBy: [datetime_DESC]
            ) {{
                action
                clientIP
                clientRequestPath
                userAgent
            }}
          }}
        }}
      }}",
      "variables": {{
        "zoneTag": "{zone_id}",
        "filter": {{
          "AND":[
            {{
              "date_geq": "{start_date}"
            }},
            {{
              "date_leq": "{end_date}"
            }}
          ]
        }}
      }}
    }}'''

    r = requests.post(url, data=payload.replace('\n', ''), headers=headers)
    return r


def get_firewall_events(historical_hours: int, filter: list) -> list:
    """
    Get firewall events using our get_cf_graphql function

    Parameters:
    historical_hours (int): Amount of hours to go back in time
    filter (list): List of strings to check in clientRequestPath


    Returns:
    list : List of dictionary events containing ip, user-agent, request-path
    """
    # TODO
    # Add more functionality to filter parameter
    # Add more data in response
    events = []
    start_date = get_past_date(historical_hours)  # Get previous time
    end_date = get_past_date(0)  # Get current time
    req = get_cf_graphql(start_date, end_date)

    if req.status_code == 200:
        if not req.json()['data']:
            return []
        for event in req.json()['data']['viewer']['zones'][0]['firewallEventsAdaptive']:
            for item in filter:
                if item in event['clientRequestPath']:
                    clientIP = event['clientIP']
                    clientUA = event['userAgent']
                    clientRP = event['clientRequestPath']
                    events.append(
                        {'ip': clientIP, 'ua': clientUA, 'rp': clientRP})
    return events


def report_abuseipdb(ip: str, comment: str, categories: str) -> requests.request:
    """
    Simple function to report abuse to AbuseIPDB

    Parameters:
    ip (str): IP Address to report
    comment (str): Comment surrounding IP
    categories (str): Categories, default is '21,19,10' which corresponds to 'Web App Attack,Bad Web Bot,Web Spam'

    Returns:
    requests.request : Response from AbuseIPDB API Endpoint
    """
    url = 'https://www.abuseipdb.com/api/v2/report'
    params = {
        'ip': ip,
        'categories': categories,
        'comment': comment,
    }

    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_key,
    }

    r = requests.post(url, headers=headers, params=params)

    return r


if __name__ == '__main__':
    # Purpose of this is to get events contains *wp*, so that is our filter
    # Later version will have graphql include the filter
    if cloudflare_email == '' or abuseipdb_key == '':
        print('Please input all required API keys and account information')

    while True:
        events = get_firewall_events(historical_hours, ['wp'])
        for event in events:
            comment = f'WordPress Scanner Reporter v1.1 - Mass scan to \'{event["rp"]}\' with user agent of \'{event["ua"]}\''
            categories = '21,19,10'
            report_abuseipdb(event['ip'], comment, categories)
            print(f'Reported {event["ip"]} for Mass wordpress scan')
            # Sleep to prevent spam of API endpoint
            time.sleep(1)
        time.sleep(60 * 60 * 1.5)
        # 1 minute * 60 minutes * 1.5 hours
