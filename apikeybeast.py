import argparse
import requests
import sys
import yaml

from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

BINARYEDGE_URL = "https://api.binaryedge.io/v2/user/subscription"
BUILTWITH_URL = "https://api.builtwith.com/usagev2/api.json"
CENSYS_URL = "https://search.censys.io/api/v1/account"
FULLHUNT_URL = "https://fullhunt.io/api/v1/auth/status"
FOFA_URL = "https://fofa.info/api/v1/info/my"
HUNTER_URL = "https://api.hunter.io/v2/account"
INTELX_URL = "https://2.intelx.io/authenticate/info"
IPINFO_URL = "https://ipinfo.io/me"
NETWORKDB_URL = "https://networksdb.io/api/key"
NETLAS_URL = "https://app.netlas.io/api/users/current/"
ONYPHE_URL = "https://www.onyphe.io/api/v2/user"
PASSIVETOTAL_URL = "https://api.passivetotal.org/v2/account/quota"
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/account/usage"
SHODAN_URL = "https://api.shodan.io/api-info"
URLSCAN_URL = "https://urlscan.io/user/quotas"
WHOISXMLAPI_URL = "https://user.whoisxmlapi.com/service/account-balance"
ZOOMEYE_URL = "https://api.zoomeye.org/user/login"

CHECK_MARK = "✅"
X_MARK = "❌"
valid = CHECK_MARK
notValid = X_MARK
support = CHECK_MARK
noSupport = X_MARK

# PROXY = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def print_banner():
    print("""
 █████╗ ██████╗ ██╗██╗  ██╗███████╗██╗   ██╗██████╗ ███████╗ █████╗ ███████╗████████╗
██╔══██╗██╔══██╗██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
███████║██████╔╝██║█████╔╝ █████╗   ╚████╔╝ ██████╔╝█████╗  ███████║███████╗   ██║   
██╔══██║██╔═══╝ ██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   
██║  ██║██║     ██║██║  ██╗███████╗   ██║   ██████╔╝███████╗██║  ██║███████║   ██║   
╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
    """)
    print("\033[1mCoded by ValluvarSploit\033[0m\n")

def get_arguments():
    parser = argparse.ArgumentParser(description=f'Usage:\n\tpython apikeybeast.py -t subfinder -f ~/.config/subfinder/provider-config.yaml\n\tpython apikeybeast.py -t amass -f ~/.config/amass/datasources.yaml',
                                 formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--tool', dest="tool", help='Specify tool name of the config file')
    parser.add_argument('-f', '--file', dest="file", help='Specify location of the config file')
    args = parser.parse_args()
    if args.file is None and args.tool is None:
        print_banner()
        parser.print_help()
        sys.exit()
    return args
    
def create_table_skeleton():
    table = Table(title="API Key Credits Detail", caption="*cpm-credits per month and cpd-credits per day", caption_justify="left" ,show_lines=True)
    table.add_column("API KEY", style="grey53", no_wrap=True)
    table.add_column("API NAME", style="cyan", no_wrap=True)
    table.add_column("PRODUCT", no_wrap=True)
    table.add_column("PLAN", no_wrap=True)
    table.add_column("CREDIT'S", no_wrap=True)
    table.add_column("USED", no_wrap=True)
    table.add_column("LEFT", style="green", no_wrap=True)
    table.add_column("RESETS ON", no_wrap=True)
    table.add_column("SUPPORT", no_wrap=True)
    table.add_column("VALID", no_wrap=True)
    # table.add_column("USERNAME", style="grey53")
    return table

def get_binary_edge_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "BinaryEdge"

    # curl https://api.binaryedge.io/v2/user/subscription -H "X-Key: apiKey" -H "Accept: application/json"
    try:
        response = requests.get(BINARYEDGE_URL, headers={"X-Key":apiKey,"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = response_json['subscription']['name']
            credits_left = response_json['requests_left']
            credits_total = response_json['requests_plan']
            credits_used = credits_total - credits_left
            credits_reset_date = response_json['end_date']

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_builtwith_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "BuiltWith"

    # curl "https://api.builtwith.com/usagev2/api.json?KEY=API_KEY" -H "Accept: application/json"
    try:
        response = requests.get(BUILTWITH_URL, params={"KEY":apiKey}, headers={"Accept":"application/json"})
        response_json = response.json()

        if response.status_code == 200 and "purchased" in response_json:
            tier = "Free"
            credits_total = response_json['purchased']
            credits_used = response_json['used']
            credits_left = response_json['remaining']

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), str(credits_reset_date), support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_censys_credits(table, apiId, apiSecret):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Censys"

    # curl -s https://search.censys.io/api/v1/account -H "Authorization: Basic "
    try:
        response = requests.get(CENSYS_URL, auth=(apiId,apiSecret), headers={"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = "Free"
            credits_total = response_json['quota']['allowance']
            credits_used = response_json['quota']['used']
            credits_left = credits_total - credits_used
            credits_reset_date = response_json['quota']['resets_at']

            table.add_row(
                f"{mask_api_key(apiId)}:{mask_api_key(apiSecret)}", api_name, product,tier, f"{credits_total} cpm", str(credits_used),str(credits_left) , credits_reset_date, support, valid
                )
        else:
            table.add_row(
                f"{mask_api_key(apiId)}:{mask_api_key(apiSecret)}", api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_fullHunt_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "FullHunt"

    # curl -s "https://fullhunt.io/api/v1/auth/status" -H "X-API-KEY: API_KEY"
    try:
        response = requests.get(FULLHUNT_URL, headers={"X-API-KEY":apiKey,"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = response_json['user']['plan']
            credits_total = response_json['user_credits']['total_credits_per_month']
            credits_used = response_json['user_credits']['credits_usage']
            credits_left = response_json['user_credits']['remaining_credits']

            table.add_row(
                mask_api_key(apiKey), api_name, product,tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_fofa_credits(table, email, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "FOFA"

    # curl -X GET "https://fofa.info/api/v1/info/my?email=email&key=apiKey"
    try:
        response = requests.get(FOFA_URL, params={"email":email,"key":apiKey}, headers={"Accept":"application/json"})
        response_json = response.json()
        
        if response.status_code == 200 and response_json['error'] == False:
            credits_total = response_json['fcoin']
            table.add_row(
                f"{mask_api_key(email)}:{mask_api_key(apiKey)}", api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                f"{mask_api_key(email)}:{mask_api_key(apiKey)}", api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")


def get_hunter_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Hunter.IO"

    try:
        response = requests.get(HUNTER_URL, params={"api_key":apiKey},headers={"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            userName = response_json['data']['email']
            tier = response_json['data']['plan_name']
            credits_total = response_json['data']['requests']['searches']['available']
            credits_used = response_json['data']['requests']['searches']['used']
            credits_left = credits_total - credits_used
            credits_reset_date = response_json['data']['reset_date']
            product = "Requests"

            table.add_row(
                mask_api_key(apiKey), api_name, product,tier, f"{credits_total} cpm", str(credits_used),str(credits_left), str(credits_reset_date), support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_intelx_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "IntelX"
    # userName = os.environ.get('INTELX_USERNAME')
    # apiKey = os.environ.get('INTELX_API_KEY')

    # curl https://2.intelx.io/authenticate/info -H "x-key: API_KEY" -H "User-Agent: IX-Python/0.5" -H "Accept: application/json"
    try:
        response = requests.get(INTELX_URL, headers={"x-key":apiKey,"User-Agent":"IX-Python/0.5", "Accept":"application/json"})
       
        if response.status_code == 200:
            response_json = response.json()
            product_paths = response_json['paths']
            tier = "Academic"
            local_product_path = ['/file/preview','/file/read','/file/view','/intelligent/search','/intelligent/search/export','/phonebook/search']

            for key, value in product_paths.items():
                if key in local_product_path:
                    if value['Path'] == "/file/preview":
                        product = "File Preview"
                    elif value['Path'] == "/file/read":
                        product = "File Read"
                    elif value['Path'] == "/file/view":
                        product = "File View"
                    elif value['Path'] == "/intelligent/search":
                        product = "Search"
                    elif value['Path'] == "/intelligent/search/export":
                        product = "Search Export"
                    elif value['Path'] == "/phonebook/search":
                        product = "Phonebook Search"
                        
                    credits_total = value['CreditMax']
                    credits_left = value['CreditMax']
                    credits_used = credits_total - credits_left
                    credits_reset_date = "Monthly"
                    
                    table.add_row(
                        mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), str(credits_reset_date), support, valid
                        )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_ipinfo_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "IPinfo"

    try:
        response = requests.get(IPINFO_URL, params={"token":apiKey}, headers={"Accept":"application/json"})
        response_json = response.json()

        if response.status_code == 200 and "token" in response_json:
            tier = "Free"
            credits_total = response_json['requests']['limit']
            credits_used = response_json['requests']['month']
            credits_left = response_json['requests']['remaining']
            credits_reset_date = "Monthly"

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier,f"{credits_total} cpm", str(credits_used),str(credits_left),str(credits_reset_date), support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_newtworkdb_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Networks DB"
    
    try:
        response = requests.get(NETWORKDB_URL, headers={"X-Api-Key":apiKey,"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = response_json['type']
            credits_total = response_json['req_limit']
            credits_used = response_json['req_count']
            credits_left = response_json['req_left']
            credits_reset_date = response_json['resets_at']

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier.title(),f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
            )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_onyphe_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Onyphe"

    try:
        response = requests.get(ONYPHE_URL, headers={"Authorization":f"apikey {apiKey}","Content-Type":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = "Free"
            credits_total = 250
            credits_left = response_json['results'][0]['credits']
            credits_used = credits_total - credits_left

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_passive_total_credits(table, userName, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Passive Total"
    # curl -s https://api.passivetotal.org/v2/account/quota -H "Authorization: Basic"
    try:
        response = requests.get(PASSIVETOTAL_URL, auth=(userName, apiKey), headers={"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = "Free"
            credits_used = response_json['user']['counts']['search_api']
            credits_total = response_json['user']['limits']['search_api']
            credits_left = credits_total - credits_used
            credits_reset_date = response_json['user']['next_reset']

            table.add_row(
                mask_api_key(apiKey), api_name, product,tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_security_trails_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Security Trails"

    try:
        response = requests.get(SECURITYTRAILS_URL, headers={"APIKEY":apiKey, "Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()
            tier = "Free"
            credits_total = response_json['allowed_monthly_usage']
            credits_used = response_json['current_monthly_usage']
            credits_left = credits_total - credits_used
            credits_reset_date = "Monthly"

            table.add_row(
                mask_api_key(apiKey), api_name, product,tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_shodan_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Shodan"

    try:
        response = requests.get(SHODAN_URL, params={"key":apiKey}, headers={"Accept":"application/json"})
        
        if response.status_code == 200:
            response_json = response.json()

            tier = response_json['plan']
            query_credits_total = response_json['usage_limits']['query_credits']
            query_credits_left = response_json['query_credits']
            query_credits_used = query_credits_total - query_credits_left
            reset_on = "Monthly"
            product = "Query"

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{str(query_credits_total)} cpm", str(query_credits_used), str(query_credits_left), reset_on, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{str(credits_total)} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )

        if response.status_code == 200:
            scan_credits_total = response_json['usage_limits']['scan_credits']
            scan_credits_left = response_json['scan_credits']
            scan_credits_used = scan_credits_total - scan_credits_left
            product = "Scan"

            table.add_row(
                mask_api_key(apiKey), api_name, product,tier, f"{str(scan_credits_total)} cpm", str(scan_credits_used), str(scan_credits_left), reset_on, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{str(credits_total)} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
            
        if response.status_code == 200:
            monitor_credits_total = response_json['usage_limits']['monitored_ips']
            monitor_credits_used = response_json['monitored_ips']
            monitor_credits_left = monitor_credits_total - monitor_credits_used
            product = "Monitor"

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{str(monitor_credits_total)} cpm", str(monitor_credits_used),str(monitor_credits_left), reset_on, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{str(credits_total)} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} {product} credits: {e}")

def get_spamhaus_credits(table, userName, password):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Spamhaus"
    # userName = os.environ.get("SPAMHAUS_USERNAME")
    # password = os.environ.get("SPAMHAUS_PASSSWORD")

    try:
        login = requests.post(
            "https://api-pdns.spamhaustech.com/v2/login?pretty", 
            json={"username":userName,"password":password}, 
            headers={"Content-Type":"application/json"},verify=False
        )

        if login.status_code == 200:
            login_json = login.json()
            jwt_access_token = login_json["token"]
        else:
            print(f"[-] An error occurred while login {api_name}")    
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")
    
    try:
        response = requests.get(
            "https://api-pdns.spamhaustech.com/v2/limits", 
            headers={"Authorization":f"Bearer {jwt_access_token}","Accept":"application/json"}
        )
        if response.status_code == 200:
            response_json = response.json()
            credits_month_total = response_json['limits']['qpm']
            credits_month_used = response_json['current']['qpm']
            credits_month_left = credits_month_total - credits_month_used

            credits_day_total = response_json['limits']['qpd']
            credits_day_used = response_json['current']['qpd']
            credits_day_left = credits_day_total - credits_day_used

            table.add_row(
                f"{mask_api_key(userName):{mask_api_key(password)}}",
                api_name, 
                product, 
                tier, 
                f"{credits_month_total} cpm\n{credits_day_total} cpd",
                f"{credits_month_used}\n{credits_day_used}",
                f"{credits_month_left}\n{credits_day_left}", 
                credits_reset_date,
                support, 
                valid
            )
        else:
            table.add_row(
                f"{mask_api_key(userName):{mask_api_key(password)}}",
                  api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_urlscan_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "URLScan.io"

    try:
        response = requests.get(URLSCAN_URL, headers={"API-Key":apiKey, "Content-Type":"application/json"})
        response_json = response.json()

        if not response_json['source'] == 'ip-address':
            tier = "Free"
            credits_total = response_json['limits']['search']['day']['limit']
            credits_used = response_json['limits']['search']['day']['used']
            credits_left = response_json['limits']['search']['day']['remaining']
            credits_reset_date = "Day"
            product = "Search"

            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
                )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_whoisxmlapi_credits(table, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "Whois XML API"

    try:
        response = requests.get(WHOISXMLAPI_URL, params={"apiKey":apiKey}, headers={"Accept":"application/json"})
        response_json = response.json()

        for item in response_json['data']:
            product = item['product']['name']
            if product == "Domain Research Suite":
                tier = "Free"
                credits_total = 500
                credits_left = item['credits']
                credits_used = credits_total - credits_left
                table.add_row(
                    mask_api_key(apiKey), api_name, product, tier, str(credits_total), str(credits_used), str(credits_left), "NA", support, valid
                    )
        else:
            table.add_row(
                mask_api_key(apiKey), api_name, product, tier, f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, notValid
                )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_zoomeye_credits(table, userName, password):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = "ZoomEye"

    try:
        login = requests.post(ZOOMEYE_URL, json={"username":userName,"password":password}, headers={"Accept":"application/json"})
       
        if login.status_code == 200:
            login_json = login.json()
            jwt_access_token = login_json['access_token']
        else:
            print(f"[-] An error occured while login to {api_name}")
    except Exception as e:
        print(f"[-] An error occured while login to Zoomeye: {e}")

    try:
        response = requests.get("https://api.zoomeye.org/resources-info", headers={"Authorization":f"JWT {jwt_access_token}","Accept":"application/json"})
        response_json = response.json()

        tier = response_json['plan']
        credits_total = response_json['quota_info']['remain_total_quota']
        credits_left = response_json['quota_info']['remain_free_quota']
        credits_used = credits_total - credits_left
        credits_reset_date = "Monthly"

        table.add_row(
            f"{mask_api_key(password):mask_api_key(userName)}", api_name, product,tier.title(), f"{credits_total} cpm", str(credits_used), str(credits_left), credits_reset_date, support, valid
            )
    except Exception as e:
        print(f"[-] An error occurred while fetching {api_name} credits: {e}")

def get_netlas_credits(table, apiKey):
    # curl https://app.netlas.io/api/users/current/ -H "X-Api-Key: <API_KEY>" -H "Content-Type: application/json"
    pass

def not_supported(table, apiName, apiKey):
    tier = "N/A"
    credits_left = 0
    credits_total = 0
    credits_used = 0
    credits_reset_date = "N/A"
    product = "N/A"
    api_name = apiName
    
    table.add_row(
        mask_api_key(apiKey), api_name, product, tier, str(credits_total), str(credits_used), str(credits_left), credits_reset_date, noSupport, ""
         )

def mask_api_key(api_key):
    if api_key is not None:
        if len(api_key) <= 5:
            return api_key
        else:
            visible_part = api_key[:2] + '**' + api_key[-3:]
            return visible_part

def call_service(table, service, apiKey):
    if service == 'binaryedge':
        get_binary_edge_credits(table, apiKey)
    elif service == 'builtwith':
        get_builtwith_credits(table, apiKey)
    elif service == 'fullhunt':
        get_fullHunt_credits(table, apiKey)
    elif service == 'hunterio':
        get_hunter_credits(table, apiKey)
    elif service == 'ipinfo':
        get_ipinfo_credits(table, apiKey)
    elif service == 'networkdb':
        get_newtworkdb_credits(table, apiKey)
    elif service == 'onyphe':
        get_onyphe_credits(table, apiKey)
    elif service == 'securitytrails':
        get_security_trails_credits(table, apiKey)
    elif service == 'shodan':
        get_shodan_credits(table, apiKey)
    elif service == 'urlscan':
        get_urlscan_credits(table, apiKey)
    elif service == 'whoisxmlapi':
        get_whoisxmlapi_credits(table, apiKey)
    else:
        not_supported(table, service, apiKey)

def main():
    ARGS = get_arguments()
    configFile = ARGS.file
    toolName = ARGS.tool

    with open(configFile, 'r') as config_file:
        yamlData = yaml.safe_load(config_file)

    table = create_table_skeleton()

    if toolName == "amass":  
        with Live(table, console=console, screen=False, refresh_per_second=20):
            for datasource in yamlData.get('datasources', []):
                service = datasource.get('name', '')
                service = service.lower()
                creds = datasource.get('creds', {})  
                for account, account_info in creds.items():
                    apiKey = str(account_info.get('apikey', ''))
                    if service == 'censys':
                        apiId = apiKey
                        apiSecret = account_info.get('secret', '')
                        get_censys_credits(table, apiId, apiSecret)
                    elif service == 'intelx':
                        get_intelx_credits(table, apiKey)
                    elif service == 'passivetotal':
                        userName = account_info.get('username', '')
                        apiKey = account_info.get('apikey', '')
                        get_passive_total_credits(table, userName, apiKey)
                    elif service == 'zoomeye':
                        userName = account_info.get('username', '')
                        password = account_info.get('password', '')
                        get_zoomeye_credits(table, userName, password)
                    elif service == 'fofa':
                        userName = account_info.get('username', '')
                        apikey = account_info.get('apikey', '')
                        get_fofa_credits(table, userName, apikey)
                    # elif service == "spamhaus":
                    #     userName = account_info.get('username', '')
                    #     password = account_info.get('password', '')
                    #     get_spamhaus_credits(table, userName, password)
                    else:
                        call_service(table, service, apiKey)
    elif toolName == "subfinder":
        with Live(table, console=console, screen=False, refresh_per_second=20): 
            for service, apiKeys in yamlData.items():
                for apiKey in apiKeys:
                    if service == 'censys':
                        apiId = apiKey.split(":")[0]
                        apiSecret = apiKey.split(":")[1]
                        get_censys_credits(table, apiId, apiSecret)
                    elif service == 'intelx':
                        apiKey = apiKey.split(":")[1]
                        get_intelx_credits(table, apiKey)
                    elif service == 'passivetotal':
                        userName = apiKey.split(":")[0]
                        apiKey = apiKey.split(":")[1]
                        get_passive_total_credits(table, userName, apiKey)
                    elif service == 'fofa':
                        userName = apiKey.split(":")[0]
                        apiKey = apiKey.split(":")[1]
                        get_fofa_credits(table, userName, apiKey)
                    else:
                        call_service(table, service, apiKey)

if __name__ == "__main__":
    main()
