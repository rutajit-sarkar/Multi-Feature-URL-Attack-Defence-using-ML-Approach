import pandas as pd
import numpy as np
import os
import ipaddress
from urllib.parse import urlparse, parse_qs
import string
import pandas as pd
import math
from collections import Counter
import socket
import geoip2.database
from datetime import datetime
import tldextract
import pandas as pd
from ipwhois import IPWhois
from datetime import datetime
import dnstwist
import dnstwist
import urllib
import re
import whois
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer


#Get URL Length of URL
def get_url_length(url):

    if not isinstance(url, str):
        raise ValueError("Input must be a string representing a URL")
    return len(url)


#CheckIPAsHostName Binary Check if IP address is used as hostname
def is_ip_address(url):
    try:
        hostname = urlparse(url).hostname
        # Check if the hostname is an IP address
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# Function to check if '.exe' is in the URL
def check_contains_exe(url):
    return '.exe' in url.lower()


#Function to compute the digit to alphabet ratio
def check_digit_alphabet_ratio(url):
    digits = sum(c.isdigit() for c in url)
    alphabets = sum(c.isalpha() for c in url)
    # Prevent division by zero
    if alphabets == 0:
        return 0.0
    return digits / alphabets


# Function to compute the ratio of special characters to alphabets in the URL
def get_specialchar_alphabet_ratio(url):
    special_chars = sum(c in string.punctuation for c in url)
    alphabets = sum(c.isalpha() for c in url)
    # Prevent division by zero
    if alphabets == 0:
        return 0.0
    return special_chars / alphabets


# Function to compute the ratio of uppercase characters to lowercase characters in the URL
def get_uppercase_lowercase_ratio(url):
    uppercase_count = sum(c.isupper() for c in url)
    lowercase_count = sum(c.islower() for c in url)
    # Prevent division by zero
    if lowercase_count == 0:
        return uppercase_count
    return uppercase_count / lowercase_count


# Function to compute the ratio of domain length to URL length
def get_domain_url_ratio(url):
    parsed_url = urlparse(url)
    domain_length = len(parsed_url.netloc)
    url_length = len(url)
    # Prevent division by zero
    if url_length == 0:
        return 0.0
    return domain_length / url_length


# Function to count numeric characters in the URL
def get_numeric_char_count(url):
    return sum(c.isdigit() for c in url)


# Function to count English letters in the URL
def get_english_letter_count(url):
    return sum(c.isalpha() for c in url)


# Function to detect if the URL uses a shortening service
def check_has_shortening_service(url):
  # Define the regular expression pattern for shortening services
  shortening_pattern = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' \
                     r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' \
                     r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|' \
                     r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|' \
                     r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|' \
                     r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|' \
                     r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|' \
                     r'tr\.im|link\.zip\.net'
  return int(re.search(shortening_pattern, url, flags=re.I) is not None)



# Function to count special characters in the URL
def get_special_char_count(url):
    return sum(c in string.punctuation for c in url)


# Function to count specific characters in the URL
def get_count_dot(url):
    return url.count('.')

def get_count_semicolon(url):
    return url.count(';')

def get_count_underscore(url):
    return url.count('_')

def get_count_question_mark(url):
    return url.count('?')

def get_count_hash(url):
    return url.count('#')

def get_count_equal(url):
    return url.count('=')

def get_count_percent_char(url):
    return url.count('%')

def get_count_ampersand(url):
    return url.count('&')

def get_count_dash(url):
    return url.count('-')

def get_count_delimiters(url):
    delimiters = '(){}[],/*/'
    return sum(url.count(d) for d in delimiters)

def get_count_at_char(url):
    return url.count('@')

def get_count_tilde_char(url):
    return url.count('∼')

def get_count_double_slash(url):
    return url.count('//')


# Function to check if URL is hashed
def check_is_hashed(url):
    return '#' in url


# Function to extract TLD from URL
def get_extract_tld(url):
    parsed_url = urlparse(url)
    # Splitting the netloc by '.' and taking the last element as TLD
    if parsed_url.netloc:
        return parsed_url.netloc.split('.')[-1]
    else:
        return ''


def get_dist_digit_alphabet(url):
    distances = []
    last_alpha_index = -1

    for i, char in enumerate(url):
        if char.isdigit():
            if last_alpha_index != -1:
                distance = i - last_alpha_index
                distances.append(distance)
        elif char.isalpha():
            last_alpha_index = i

    if not distances:
        return 0.0

    avg_distance = sum(distances) / len(distances)
    return avg_distance

def get_has_https(url):
    return 1 if "https" in url else 0

def get_extract_file_extension(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    if '.' in os.path.basename(path):
        return os.path.splitext(os.path.basename(path))[1]
    else:
        return ''

# Function to check if subdomain contains TLD or ccTLD
def check_has_tld_in_subdomain(url):
    try:
        # Extract subdomain, domain, and suffix using tldextract
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        suffix = extracted.suffix

        # List of TLDs and ccTLDs
        tlds = [
    "aaa", "aarp", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi", "ac", "academy", "accenture",
    "accountant", "accountants", "aco", "actor", "ad", "ads", "adult", "ae", "aeg", "aero", "aetna", "af", "afl",
    "africa", "ag", "agakhan", "agency", "ai", "aig", "airbus", "airforce", "airtel", "akdn", "al", "alibaba",
    "alipay","allfinanz", "allstate", "ally", "alsace", "alstom", "am", "amazon", "americanexpress", "americanfamily",
    "amex","amfam", "amica", "amsterdam", "analytics", "android", "anquan", "anz", "ao", "aol", "apartments", "app", "apple",
    "aq", "aquarelle", "ar", "arab", "aramco", "archi", "army", "arpa", "art", "arte", "as", "asda", "asia", "associates",
    "at", "athleta", "attorney", "au", "auction", "audi", "audible", "audio", "auspost", "author", "auto", "autos", "aw",
    "aws", "ax", "axa", "az", "azure", "ba", "baby", "baidu", "banamex", "band", "bank", "bar", "barcelona", "barclaycard",
    "barclays", "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern", "bb", "bbc", "bbt", "bbva", "bcg",
    "bcn", "bd", "be", "beats", "beauty", "beer", "bentley", "berlin", "best", "bestbuy", "bet", "bf", "bg", "bh", "bharti",
    "bi", "bible", "bid", "bike", "bing", "bingo", "bio", "biz", "bj", "black", "blackfriday", "blockbuster", "blog",
    "bloomberg", "blue", "bm", "bms", "bmw", "bn", "bnpparibas", "bo", "boats", "boehringer", "bofa", "bom", "bond", "boo",
    "book", "booking", "bosch", "bostik", "boston", "bot", "boutique", "box", "br", "bradesco", "bridgestone", "broadway",
    "broker", "brother", "brussels", "bs", "bt", "build", "builders", "business", "buy", "buzz", "bv", "bw", "by", "bz",
    "bzh", "ca", "cab", "cafe", "cal", "call", "calvinklein", "cam", "camera", "camp", "canon", "capetown", "capital",
    "capitalone", "car", "caravan", "cards", "care", "career", "careers", "cars", "casa", "case", "cash", "casino", "cat",
    "catering", "catholic", "cba", "cbn", "cbre", "cc", "cd", "center", "ceo", "cern", "cf", "cfa", "cfd", "cg", "ch",
    "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai", "christmas", "chrome", "church", "ci", "cipriani",
    "circle", "cisco", "citadel", "citi", "citic", "city", "ck", "cl", "claims", "cleaning", "click", "clinic", "clinique",
    "clothing", "cloud", "club", "clubmed", "cm", "cn", "co", "coach", "codes", "coffee", "college", "cologne", "com",
    "commbank", "community", "company", "compare", "computer", "comsec", "condos", "construction", "consulting", "contact",
    "contractors", "cooking", "cool", "coop", "corsica", "country", "coupon", "coupons", "courses", "cpa", "cr", "credit",
    "creditcard", "creditunion", "cricket", "crown", "crs", "cruise", "cruises", "cu", "cuisinella", "cv", "cw", "cx", "cy",
    "cymru", "cyou", "cz", "dabur", "dad", "dance", "data", "date", "dating", "datsun", "day", "dclk", "dds", "de", "deal",
    "dealer", "deals", "degree", "delivery", "dell", "deloitte", "delta", "democrat", "dental", "dentist", "desi", "design",
    "dev", "dhl", "diamonds", "diet", "digital", "direct", "directory", "discount", "discover", "dish", "diy", "dj", "dk",
    "dm", "dnp", "do", "docs", "doctor", "dog", "domains", "dot", "download", "drive", "dtv", "dubai", "dunlop", "dupont",
    "durban", "dvag", "dvr", "dz", "earth", "eat", "ec", "eco", "edeka", "edu", "education", "ee", "eg", "email", "emerck",
    "energy", "engineer", "engineering", "enterprises", "epson", "equipment", "er", "ericsson", "erni", "es", "esq", "estate",
    "et", "eu", "eurovision", "eus", "events", "exchange", "expert", "exposed", "express", "extraspace", "fage", "fail",
    "fairwinds", "faith", "family", "fan", "fans", "farm", "farmers", "fashion", "fast", "fedex", "feedback", "ferrari",
    "ferrero", "fi", "fidelity", "fido", "film", "final", "finance", "financial", "fire", "firestone", "firmdale", "fish",
    "fishing", "fit", "fitness", "fj", "fk", "flickr", "flights", "flir", "florist", "flowers", "fly", "fm", "fo", "foo",
    "food", "football", "ford", "forex", "forsale", "forum", "foundation", "fox", "fr", "free", "fresenius", "frl", "frogans",
    "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol", "fyi", "ga", "gal", "gallery", "gallo", "gallup", "game",
    "games", "gap", "garden", "gay", "gb", "gbiz", "gd", "gdn", "ge", "gea", "gent", "genting", "george", "gf", "gg", "ggee",
    "gh", "gi", "gift", "gifts", "gives", "giving", "gl", "glass", "gle", "global", "globo", "gm", "gmail", "gmbh", "gmo",
    "gmx", "gn", "godaddy", "gold", "goldpoint", "golf", "goo", "goodyear", "goog", "google", "gop", "got", "gov", "gp", "gq",
    "gr", "grainger", "graphics", "gratis", "green", "gripe", "grocery", "group", "gs", "gt", "gu", "gucci", "guge", "guide",
    "guitars", "guru", "gw", "gy", "hair", "hamburg", "hangout", "haus", "hbo", "hdfc", "hdfcbank", "health", "healthcare",
    "help", "helsinki", "here", "hermes", "hiphop", "hisamitsu", "hitachi", "hiv", "hk", "hkt", "hm", "hn", "hockey", "holdings",
    "holiday", "homedepot", "homegoods", "homes", "homesense", "honda", "horse", "hospital", "host", "hosting", "hot", "hotels",
    "hotmail", "house", "how", "hr", "hsbc", "ht", "hu", "hughes", "hyatt", "hyundai", "ibm", "icbc",
    "ice", "icu", "id","ie", "ieee", "ifm", "ikano", "il", "im", "imamat", "imdb", "immo", "immobilien", "in", "inc", "industries", "infiniti",
    "info", "ing", "ink", "institute", "insurance", "insure", "int", "intel", "international", "intuit", "investments",
    "io", "ipiranga", "iq", "ir", "irish", "is", "iselect", "ismaili", "ist", "istanbul", "it", "itau", "itv", "iveco",
    "iwc", "jaguar", "java", "jcb", "jcp", "je", "jeep", "jetzt", "jewelry", "jio", "jlc", "jll", "jm", "jmp", "jnj",
    "jo", "jobs", "joburg", "jot", "joy", "jp", "jpmorgan", "jprs", "juegos", "juniper", "kaufen", "kddi", "ke", "kerryhotels",
    "kerrylogistics", "kerryproperties", "kfh", "kg", "kh", "ki", "kia", "kids", "kim", "kinder", "kindle", "kitchen", "kiwi",
    "km", "kn", "koeln", "komatsu", "kosher", "kp", "kpmg", "kpn", "kr", "krd", "kred", "kuokgroup", "kw", "ky", "kyoto",
    "kz", "la", "lacaixa", "lamborghini", "lamer", "lancaster", "lancia", "lancome", "land", "landrover", "lanxess",
    "lasalle", "lat", "latino", "latrobe", "law", "lawyer", "lb", "lc", "lds", "lease", "leclerc", "lefrak", "legal",
    "lego", "lexus", "lgbt", "li", "lidl", "life", "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited",
    "limo", "lincoln", "linde", "link", "lipsy", "live", "living", "lixil", "lk", "loan", "loans", "locker", "locus", "loft",
    "lol", "london", "lotte", "lotto", "love", "lpl", "lplfinancial", "lr", "ls", "lt", "ltd", "ltda", "lu", "lundbeck",
    "luxe", "luxury", "lv", "ly", "ma", "macys", "madrid", "maif", "maison", "makeup", "man", "management", "mango", "map",
    "market", "marketing", "markets", "marriott", "marshalls", "maserati", "mattel", "mba", "mc", "mckinsey", "md", "me",
    "med", "media", "meet", "melbourne", "meme", "memorial", "men", "menu", "merckmsd", "metlife", "mg", "mh", "miami",
    "microsoft", "mil", "mini", "mint", "mit", "mitsubishi", "mk", "ml", "mlb", "mls", "mm", "mma", "mn", "mo", "mobi",
    "mobile", "mobily", "moda", "moe", "moi", "mom", "monash", "money", "monster", "mopar", "mormon", "mortgage", "moscow",
    "moto", "motorcycles", "mov", "movie", "movistar", "mp", "mq", "mr", "ms", "msd", "mt", "mtn", "mtr", "mu", "museum",
    "mutual", "mv", "mw", "mx", "my", "mz", "na", "nab", "nadex", "nagoya", "name", "natura", "navy", "nba", "nc", "ne",
    "nec", "net", "netbank", "netflix", "network", "neustar", "new", "newholland", "news", "next", "nextdirect", "nexus",
    "nf", "nfl", "ng", "ngo", "nhk", "ni", "nico", "nike", "nikon", "ninja", "nissan", "nissay", "nl", "no", "nokia",
    "northwesternmutual", "norton", "now", "nowruz", "nowtv", "np", "nr", "nra", "nrw", "ntt", "nu", "nyc", "nz", "obi",
    "observer", "off", "office", "okinawa", "olayan", "olayangroup", "oldnavy", "ollo", "om", "omega", "one", "ong",
    "onl", "online", "onyourside", "ooo", "open", "oracle", "orange", "org", "organic", "origins", "osaka", "otsuka",
    "ott", "ovh", "pa", "page", "panasonic", "paris", "pars", "partners", "parts", "party", "passagens", "pay", "pccw",
    "pe", "pet", "pf", "pfizer", "pg", "ph", "pharmacy", "phd", "philips", "phone", "photo", "photography", "photos",
    "physio", "piaget", "pics", "pictet", "pictures", "pid", "pin", "ping", "pink", "pioneer", "pizza", "pk", "pl", "place",
    "play", "playstation", "plumbing", "plus", "pm", "pn", "pnc", "pohl", "poker", "politie", "porn", "post", "pr", "pramerica",
    "praxi", "press", "prime", "pro", "prod", "productions", "prof", "progressive", "promo", "properties", "property",
    "protection", "pru", "prudential", "ps", "pt", "pub", "pw", "pwc", "py", "qa", "qpon", "quebec", "quest", "qvc",
    "racing", "radio", "raid", "re", "read", "realestate", "realtor", "realty", "recipes", "red", "redstone", "redumbrella",
    "rehab", "reise", "reisen", "reit", "reliance", "ren", "rent", "rentals", "repair", "report", "republican", "rest",
    "restaurant", "review", "reviews", "rexroth", "rich", "richardli", "ricoh", "rightathome", "ril", "rio", "rip",
    "rmit", "ro", "rocher", "rocks", "rodeo", "rogers", "room", "rs", "rsvp", "ru", "rugby", "ruhr", "run", "rw",
    "rwe", "ryukyu", "sa", "saarland", "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung", "sandvik",
    "sandvikcoromant", "sanofi", "sap", "sapo", "sarl", "sas", "save", "saxo", "sb", "sbi", "sbs", "sc", "sca", "scb",
    "schaeffler", "schmidt", "scholarships", "school", "schule", "schwarz", "science", "scjohnson", "scor", "scot",
    "sd", "se", "search", "seat", "secure", "security", "seek", "select", "sener", "services", "ses", "seven", "sew",
    "sex", "sexy", "sfr", "sg", "sh", "shangrila", "sharp", "shaw", "shell", "shia", "shiksha", "shoes", "shop", "shopping",
    "shouji", "show", "showtime", "si", "silk", "sina", "singles", "site", "ski", "skin", "sky", "skype", "sl", "sling",
    "sm", "smart", "smile", "sn", "sncf", "so", "soccer", "social", "softbank", "software", "sohu", "solar", "solutions",
    "song", "sony", "soy", "spa", "space", "sport", "spot", "spreadbetting", "sr", "srl", "ss", "st", "stada", "staples",
    "star", "starhub", "statebank", "statefarm", "statoil", "stc", "stcgroup", "stockholm", "storage", "store", "stream",
    "studio", "study", "style", "su", "sucks", "supplies", "supply", "support", "surf", "surgery", "suzuki", "sv",
    "swatch", "swiftcover", "swiss", "sx", "sy", "sydney", "symantec", "systems", "sz", "tab", "taipei", "talk", "taobao",
    "target", "tatamotors", "tatar", "tattoo", "tax", "taxi", "tc", "tci", "td", "tdk", "team", "tech", "technology",
    "tel", "telecity", "telefonica", "temasek", "tennis", "teva", "tf", "tg", "th", "thd", "theater", "theatre", "tiaa",
    "tickets", "tienda", "tiffany", "tips", "tires", "tirol", "tjmaxx", "tjx", "tk", "tl", "tm", "tmall", "tn", "to",
    "today", "tokyo", "tools", "top", "toray", "toshiba", "total", "tours", "town", "toyota", "toys", "tr", "trade",
    "trading", "training", "travel", "travelchannel", "travelers", "travelersinsurance", "trust", "trv", "tt", "tube",
    "tui", "tunes", "tushu", "tv", "tvs", "tw", "tz", "ua", "ubank", "ubs", "uconnect", "ug", "uk", "unicom", "university",
    "uno", "uol", "ups", "us", "uy", "uz", "va", "vacations", "vana", "vanguard", "vc", "ve", "vegas", "ventures",
    "verisign", "versicherung", "vet", "vg", "vi", "viajes", "video", "vig", "viking", "villas", "vin", "vip", "virgin",
    "visa", "vision", "vista", "vistaprint", "viva", "vivo", "vlaanderen", "vn", "vodka", "volkswagen", "volvo", "vote",
    "voting", "voto", "voyage", "vu", "vuelos", "wales", "walmart", "walter", "wang", "wanggou", "warman", "watch",
    "watches", "weather", "web", "webcam", "weber", "website", "wed", "wedding", "weibo", "weir", "wf", "whoswho", "wien",
    "wiki", "williamhill", "win", "windows", "wine", "winners", "wme", "wolterskluwer", "woodside", "work", "works",
    "world", "wow", "ws", "wtc", "wtf", "xbox", "xerox", "xfinity", "xihuan", "xin", "xn", "xxx", "xyz", "yachts", "yahoo",
    "yamaxun", "yandex", "ye", "yodobashi", "yoga", "yokohama", "you", "youtube", "yt", "yun", "za", "zappos", "zara",
    "zero", "zip", "zippo", "zm", "zone", "zuerich", "zw"]

        # Check if subdomain or domain contains a TLD or ccTLD
        if subdomain and subdomain in tlds:
            return True
        else:
            return False

    except Exception as e:
        print(f"Error checking TLD in subdomain for {url}: {str(e)}")
        return None


# Function to check if TLD or ccTLD is in path of URL
def check_has_tld_in_path(url):
    parsed_url = urlparse(url)
    path_components = parsed_url.path.split('/')

    # List of common TLDs and ccTLDs
    tlds = [
    "aaa", "aarp", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi", "ac", "academy", "accenture",
    "accountant", "accountants", "aco", "actor", "ad", "ads", "adult", "ae", "aeg", "aero", "aetna", "af", "afl",
    "africa", "ag", "agakhan", "agency", "ai", "aig", "airbus", "airforce", "airtel", "akdn", "al", "alibaba",
    "alipay","allfinanz", "allstate", "ally", "alsace", "alstom", "am", "amazon", "americanexpress", "americanfamily",
    "amex","amfam", "amica", "amsterdam", "analytics", "android", "anquan", "anz", "ao", "aol", "apartments", "app", "apple",
    "aq", "aquarelle", "ar", "arab", "aramco", "archi", "army", "arpa", "art", "arte", "as", "asda", "asia", "associates",
    "at", "athleta", "attorney", "au", "auction", "audi", "audible", "audio", "auspost", "author", "auto", "autos", "aw",
    "aws", "ax", "axa", "az", "azure", "ba", "baby", "baidu", "banamex", "band", "bank", "bar", "barcelona", "barclaycard",
    "barclays", "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern", "bb", "bbc", "bbt", "bbva", "bcg",
    "bcn", "bd", "be", "beats", "beauty", "beer", "bentley", "berlin", "best", "bestbuy", "bet", "bf", "bg", "bh", "bharti",
    "bi", "bible", "bid", "bike", "bing", "bingo", "bio", "biz", "bj", "black", "blackfriday", "blockbuster", "blog",
    "bloomberg", "blue", "bm", "bms", "bmw", "bn", "bnpparibas", "bo", "boats", "boehringer", "bofa", "bom", "bond", "boo",
    "book", "booking", "bosch", "bostik", "boston", "bot", "boutique", "box", "br", "bradesco", "bridgestone", "broadway",
    "broker", "brother", "brussels", "bs", "bt", "build", "builders", "business", "buy", "buzz", "bv", "bw", "by", "bz",
    "bzh", "ca", "cab", "cafe", "cal", "call", "calvinklein", "cam", "camera", "camp", "canon", "capetown", "capital",
    "capitalone", "car", "caravan", "cards", "care", "career", "careers", "cars", "casa", "case", "cash", "casino", "cat",
    "catering", "catholic", "cba", "cbn", "cbre", "cc", "cd", "center", "ceo", "cern", "cf", "cfa", "cfd", "cg", "ch",
    "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai", "christmas", "chrome", "church", "ci", "cipriani",
    "circle", "cisco", "citadel", "citi", "citic", "city", "ck", "cl", "claims", "cleaning", "click", "clinic", "clinique",
    "clothing", "cloud", "club", "clubmed", "cm", "cn", "co", "coach", "codes", "coffee", "college", "cologne", "com",
    "commbank", "community", "company", "compare", "computer", "comsec", "condos", "construction", "consulting", "contact",
    "contractors", "cooking", "cool", "coop", "corsica", "country", "coupon", "coupons", "courses", "cpa", "cr", "credit",
    "creditcard", "creditunion", "cricket", "crown", "crs", "cruise", "cruises", "cu", "cuisinella", "cv", "cw", "cx", "cy",
    "cymru", "cyou", "cz", "dabur", "dad", "dance", "data", "date", "dating", "datsun", "day", "dclk", "dds", "de", "deal",
    "dealer", "deals", "degree", "delivery", "dell", "deloitte", "delta", "democrat", "dental", "dentist", "desi", "design",
    "dev", "dhl", "diamonds", "diet", "digital", "direct", "directory", "discount", "discover", "dish", "diy", "dj", "dk",
    "dm", "dnp", "do", "docs", "doctor", "dog", "domains", "dot", "download", "drive", "dtv", "dubai", "dunlop", "dupont",
    "durban", "dvag", "dvr", "dz", "earth", "eat", "ec", "eco", "edeka", "edu", "education", "ee", "eg", "email", "emerck",
    "energy", "engineer", "engineering", "enterprises", "epson", "equipment", "er", "ericsson", "erni", "es", "esq", "estate",
    "et", "eu", "eurovision", "eus", "events", "exchange", "expert", "exposed", "express", "extraspace", "fage", "fail",
    "fairwinds", "faith", "family", "fan", "fans", "farm", "farmers", "fashion", "fast", "fedex", "feedback", "ferrari",
    "ferrero", "fi", "fidelity", "fido", "film", "final", "finance", "financial", "fire", "firestone", "firmdale", "fish",
    "fishing", "fit", "fitness", "fj", "fk", "flickr", "flights", "flir", "florist", "flowers", "fly", "fm", "fo", "foo",
    "food", "football", "ford", "forex", "forsale", "forum", "foundation", "fox", "fr", "free", "fresenius", "frl", "frogans",
    "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol", "fyi", "ga", "gal", "gallery", "gallo", "gallup", "game",
    "games", "gap", "garden", "gay", "gb", "gbiz", "gd", "gdn", "ge", "gea", "gent", "genting", "george", "gf", "gg", "ggee",
    "gh", "gi", "gift", "gifts", "gives", "giving", "gl", "glass", "gle", "global", "globo", "gm", "gmail", "gmbh", "gmo",
    "gmx", "gn", "godaddy", "gold", "goldpoint", "golf", "goo", "goodyear", "goog", "google", "gop", "got", "gov", "gp", "gq",
    "gr", "grainger", "graphics", "gratis", "green", "gripe", "grocery", "group", "gs", "gt", "gu", "gucci", "guge", "guide",
    "guitars", "guru", "gw", "gy", "hair", "hamburg", "hangout", "haus", "hbo", "hdfc", "hdfcbank", "health", "healthcare",
    "help", "helsinki", "here", "hermes", "hiphop", "hisamitsu", "hitachi", "hiv", "hk", "hkt", "hm", "hn", "hockey", "holdings",
    "holiday", "homedepot", "homegoods", "homes", "homesense", "honda", "horse", "hospital", "host", "hosting", "hot", "hotels",
    "hotmail", "house", "how", "hr", "hsbc", "ht", "hu", "hughes", "hyatt", "hyundai", "ibm", "icbc",
    "ice", "icu", "id","ie", "ieee", "ifm", "ikano", "il", "im", "imamat", "imdb", "immo", "immobilien", "in", "inc", "industries", "infiniti",
    "info", "ing", "ink", "institute", "insurance", "insure", "int", "intel", "international", "intuit", "investments",
    "io", "ipiranga", "iq", "ir", "irish", "is", "iselect", "ismaili", "ist", "istanbul", "it", "itau", "itv", "iveco",
    "iwc", "jaguar", "java", "jcb", "jcp", "je", "jeep", "jetzt", "jewelry", "jio", "jlc", "jll", "jm", "jmp", "jnj",
    "jo", "jobs", "joburg", "jot", "joy", "jp", "jpmorgan", "jprs", "juegos", "juniper", "kaufen", "kddi", "ke", "kerryhotels",
    "kerrylogistics", "kerryproperties", "kfh", "kg", "kh", "ki", "kia", "kids", "kim", "kinder", "kindle", "kitchen", "kiwi",
    "km", "kn", "koeln", "komatsu", "kosher", "kp", "kpmg", "kpn", "kr", "krd", "kred", "kuokgroup", "kw", "ky", "kyoto",
    "kz", "la", "lacaixa", "lamborghini", "lamer", "lancaster", "lancia", "lancome", "land", "landrover", "lanxess",
    "lasalle", "lat", "latino", "latrobe", "law", "lawyer", "lb", "lc", "lds", "lease", "leclerc", "lefrak", "legal",
    "lego", "lexus", "lgbt", "li", "lidl", "life", "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited",
    "limo", "lincoln", "linde", "link", "lipsy", "live", "living", "lixil", "lk", "loan", "loans", "locker", "locus", "loft",
    "lol", "london", "lotte", "lotto", "love", "lpl", "lplfinancial", "lr", "ls", "lt", "ltd", "ltda", "lu", "lundbeck",
    "luxe", "luxury", "lv", "ly", "ma", "macys", "madrid", "maif", "maison", "makeup", "man", "management", "mango", "map",
    "market", "marketing", "markets", "marriott", "marshalls", "maserati", "mattel", "mba", "mc", "mckinsey", "md", "me",
    "med", "media", "meet", "melbourne", "meme", "memorial", "men", "menu", "merckmsd", "metlife", "mg", "mh", "miami",
    "microsoft", "mil", "mini", "mint", "mit", "mitsubishi", "mk", "ml", "mlb", "mls", "mm", "mma", "mn", "mo", "mobi",
    "mobile", "mobily", "moda", "moe", "moi", "mom", "monash", "money", "monster", "mopar", "mormon", "mortgage", "moscow",
    "moto", "motorcycles", "mov", "movie", "movistar", "mp", "mq", "mr", "ms", "msd", "mt", "mtn", "mtr", "mu", "museum",
    "mutual", "mv", "mw", "mx", "my", "mz", "na", "nab", "nadex", "nagoya", "name", "natura", "navy", "nba", "nc", "ne",
    "nec", "net", "netbank", "netflix", "network", "neustar", "new", "newholland", "news", "next", "nextdirect", "nexus",
    "nf", "nfl", "ng", "ngo", "nhk", "ni", "nico", "nike", "nikon", "ninja", "nissan", "nissay", "nl", "no", "nokia",
    "northwesternmutual", "norton", "now", "nowruz", "nowtv", "np", "nr", "nra", "nrw", "ntt", "nu", "nyc", "nz", "obi",
    "observer", "off", "office", "okinawa", "olayan", "olayangroup", "oldnavy", "ollo", "om", "omega", "one", "ong",
    "onl", "online", "onyourside", "ooo", "open", "oracle", "orange", "org", "organic", "origins", "osaka", "otsuka",
    "ott", "ovh", "pa", "page", "panasonic", "paris", "pars", "partners", "parts", "party", "passagens", "pay", "pccw",
    "pe", "pet", "pf", "pfizer", "pg", "ph", "pharmacy", "phd", "philips", "phone", "photo", "photography", "photos",
    "physio", "piaget", "pics", "pictet", "pictures", "pid", "pin", "ping", "pink", "pioneer", "pizza", "pk", "pl", "place",
    "play", "playstation", "plumbing", "plus", "pm", "pn", "pnc", "pohl", "poker", "politie", "porn", "post", "pr", "pramerica",
    "praxi", "press", "prime", "pro", "prod", "productions", "prof", "progressive", "promo", "properties", "property",
    "protection", "pru", "prudential", "ps", "pt", "pub", "pw", "pwc", "py", "qa", "qpon", "quebec", "quest", "qvc",
    "racing", "radio", "raid", "re", "read", "realestate", "realtor", "realty", "recipes", "red", "redstone", "redumbrella",
    "rehab", "reise", "reisen", "reit", "reliance", "ren", "rent", "rentals", "repair", "report", "republican", "rest",
    "restaurant", "review", "reviews", "rexroth", "rich", "richardli", "ricoh", "rightathome", "ril", "rio", "rip",
    "rmit", "ro", "rocher", "rocks", "rodeo", "rogers", "room", "rs", "rsvp", "ru", "rugby", "ruhr", "run", "rw",
    "rwe", "ryukyu", "sa", "saarland", "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung", "sandvik",
    "sandvikcoromant", "sanofi", "sap", "sapo", "sarl", "sas", "save", "saxo", "sb", "sbi", "sbs", "sc", "sca", "scb",
    "schaeffler", "schmidt", "scholarships", "school", "schule", "schwarz", "science", "scjohnson", "scor", "scot",
    "sd", "se", "search", "seat", "secure", "security", "seek", "select", "sener", "services", "ses", "seven", "sew",
    "sex", "sexy", "sfr", "sg", "sh", "shangrila", "sharp", "shaw", "shell", "shia", "shiksha", "shoes", "shop", "shopping",
    "shouji", "show", "showtime", "si", "silk", "sina", "singles", "site", "ski", "skin", "sky", "skype", "sl", "sling",
    "sm", "smart", "smile", "sn", "sncf", "so", "soccer", "social", "softbank", "software", "sohu", "solar", "solutions",
    "song", "sony", "soy", "spa", "space", "sport", "spot", "spreadbetting", "sr", "srl", "ss", "st", "stada", "staples",
    "star", "starhub", "statebank", "statefarm", "statoil", "stc", "stcgroup", "stockholm", "storage", "store", "stream",
    "studio", "study", "style", "su", "sucks", "supplies", "supply", "support", "surf", "surgery", "suzuki", "sv",
    "swatch", "swiftcover", "swiss", "sx", "sy", "sydney", "symantec", "systems", "sz", "tab", "taipei", "talk", "taobao",
    "target", "tatamotors", "tatar", "tattoo", "tax", "taxi", "tc", "tci", "td", "tdk", "team", "tech", "technology",
    "tel", "telecity", "telefonica", "temasek", "tennis", "teva", "tf", "tg", "th", "thd", "theater", "theatre", "tiaa",
    "tickets", "tienda", "tiffany", "tips", "tires", "tirol", "tjmaxx", "tjx", "tk", "tl", "tm", "tmall", "tn", "to",
    "today", "tokyo", "tools", "top", "toray", "toshiba", "total", "tours", "town", "toyota", "toys", "tr", "trade",
    "trading", "training", "travel", "travelchannel", "travelers", "travelersinsurance", "trust", "trv", "tt", "tube",
    "tui", "tunes", "tushu", "tv", "tvs", "tw", "tz", "ua", "ubank", "ubs", "uconnect", "ug", "uk", "unicom", "university",
    "uno", "uol", "ups", "us", "uy", "uz", "va", "vacations", "vana", "vanguard", "vc", "ve", "vegas", "ventures",
    "verisign", "versicherung", "vet", "vg", "vi", "viajes", "video", "vig", "viking", "villas", "vin", "vip", "virgin",
    "visa", "vision", "vista", "vistaprint", "viva", "vivo", "vlaanderen", "vn", "vodka", "volkswagen", "volvo", "vote",
    "voting", "voto", "voyage", "vu", "vuelos", "wales", "walmart", "walter", "wang", "wanggou", "warman", "watch",
    "watches", "weather", "web", "webcam", "weber", "website", "wed", "wedding", "weibo", "weir", "wf", "whoswho", "wien",
    "wiki", "williamhill", "win", "windows", "wine", "winners", "wme", "wolterskluwer", "woodside", "work", "works",
    "world", "wow", "ws", "wtc", "wtf", "xbox", "xerox", "xfinity", "xihuan", "xin", "xn", "xxx", "xyz", "yachts", "yahoo",
    "yamaxun", "yandex", "ye", "yodobashi", "yoga", "yokohama", "you", "youtube", "yt", "yun", "za", "zappos", "zara",
    "zero", "zip", "zippo", "zm", "zone", "zuerich", "zw"]
    # Check if any path component ends with a TLD or ccTLD
    for component in path_components:
        for tld in tlds:
            if component.endswith(tld):
                return 1
    return 0


# Function to check for disarranged "https" in hostname
def check_has_disarranged_https(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # Check if hostname is None (invalid URL) or "https" is in hostname not in standard form
    if hostname and "https" in hostname and hostname != "https" and not hostname.startswith("https"):
        return 1
    else:
        return 0



# Function to calculate hostname length
def get_hostname_length(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname:
        return len(hostname)
    else:
        return 0  # Return 0 if hostname is not present


# Function to calculate path length
def get_path_length(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    return len(path)


# Function to calculate query length
def get_query_length(url):
    parsed_url = urlparse(url)
    query = parsed_url.query

    # Parse the query string to get individual parameters (if needed)
    parsed_query = parse_qs(query)

    # Return the length of the query string
    return len(query)


# List of anonymous words to check for
anonymous_words = ["personal", ".bin", "abuse",
    "anonymous",
    "private",
    "hidden",
    "secret",
    "proxy",
    "unidentified",
    "masked",
    "burner",
    "anonymize",
    "anonymity",
    "stealth",
    "untraceable",
    "offshore",
    "encrypted",
    "secure communication",
    "secure connection",
    "secure browsing",
    "ghost",
    "cloak",
    "obfuscate",
    "TOR",
    "VPN",
    "I2P"
]

# Function to check for anonymous words in URL
def check_has_anonymous_words(url):
    for word in anonymous_words:
        if word in url:
            return 1
    return 0


def check_has_www(url):
    if 'www' in url:
        return 1
    else:
        return 0

# Function to check for presence of "ftp://" in URL
def check_has_ftp(url):
    if 'ftp://' in url:
        return 1
    else:
        return 0

# Function to check for presence of ".js" in URL
def check_has_js(url):
    if '.js' in url:
        return 1
    else:
        return 0


# Function to check for presence of "files" in URL
def check_has_files(url):
    if 'files' in url:
        return 1
    else:
        return 0

#Function to check 'css'
def check_has_css(url):
    if '.css' in url:
        return 1
    else:
        return 0



# Function to check if domain is random
def check_is_domain_random(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if domain is None:
            return 0

        domain_parts = domain.split('.')

        # Extract second-level domain (example.co.uk -> example)
        if len(domain_parts) >= 2:
            second_level_domain = domain_parts[-2]

            alphanumeric_chars = set(string.ascii_letters + string.digits)  # Set of alphanumeric characters

            # Check if domain contains only alphanumeric characters and has length > 5 (arbitrary threshold)
            if all(char.lower() in alphanumeric_chars for char in second_level_domain) and len(second_level_domain) > 5:
                return 1
            else:
                return 0
        else:
            return 0

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


# List of sensitive words
sensitive_words = ['secure', 'account', 'webscr', 'login','confirm', 'account',  'banking', 'signin']

# Function to count sensitive words in a URL
def get_count_sensitive_words(url):
    url_lower = url.lower()  # Convert URL to lowercase for case insensitivity
    count = sum(url_lower.count(word) for word in sensitive_words)
    return count


def check_shannon_entropy(url):
    # Remove protocol and domain part, if any, and consider the path/query/fragment part for entropy calculation
    if '://' in url:
        url = url.split('://')[1]
    url = url.split('/')[0]  # Consider only the path/query/fragment part

    # Calculate character frequencies
    char_count = Counter(url.lower())  # Convert to lowercase for case insensitivity
    total_chars = sum(char_count.values())

    # Calculate entropy
    entropy = 0
    for count in char_count.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)

    return entropy

# Function to get hyphenated domain name from URL
def check_hyphenated_domain(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')

    # Remove 'www' or other subdomains
    if domain_parts[0] == 'www':
        domain_parts = domain_parts[1:]

    # Create hyphenated domain string
    hyphenated_domain_str = '-'.join(domain_parts)

    return hyphenated_domain_str


#function to detect homogylphs string
def detect_homoglyphs(url):
    homoglyphs = {
    'а': 'a', 'ɑ': 'a', 'ä': 'a', 'á': 'a', 'à': 'a', 'â': 'a', 'å': 'a', 'ã': 'a', 'ā': 'a',
    'Ь': 'b', 'Ƅ': 'b', 'ɓ': 'b',
    'ḉ': 'c', 'ç': 'c', 'ċ': 'c', 'ć': 'c', 'č': 'c', 'ĉ': 'c',
    'Ď': 'd', 'ď': 'd', 'đ': 'd', 'ḋ': 'd',
    'е': 'e', 'ë': 'e', 'é': 'e', 'è': 'e', 'ê': 'e', 'ē': 'e', 'ė': 'e', 'ę': 'e', 'ĕ': 'e', 'ě': 'e',
    'ƒ': 'f', 'ḟ': 'f',
    'ĝ': 'g', 'ğ': 'g', 'ġ': 'g', 'ģ': 'g',
    'Ĥ': 'h', 'Ħ': 'h', 'ḧ': 'h',
    'і': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i', 'į': 'i', 'ĭ': 'i', 'ı': 'i',
    'Ј': 'j', 'ĵ': 'j',
    'к': 'k', 'ĸ': 'k', 'ķ': 'k',
    'Ĺ': 'l', 'ĺ': 'l', 'ļ': 'l', 'ľ': 'l', 'ŀ': 'l', 'ł': 'l',
    'м': 'm', 'ṁ': 'm',
    'ñ': 'n', 'ń': 'n', 'ņ': 'n', 'ň': 'n', 'ŋ': 'n', 'ṅ': 'n',
    'о': 'o', 'ö': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ø': 'o', 'ō': 'o', 'ŏ': 'o', 'ő': 'o',
    'Ρ': 'p', 'р': 'p', 'ƥ': 'p', 'ṗ': 'p',
    'ř': 'r', 'ŕ': 'r', 'ŗ': 'r', 'ṙ': 'r',
    'Ş': 's', 'ś': 's', 'š': 's', 'ŝ': 's', 'ș': 's', 'ṡ': 's',
    'ť': 't', 'ţ': 't', 'ŧ': 't', 'ṫ': 't',
    'υ': 'u', 'ü': 'u', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ū': 'u', 'ŭ': 'u', 'ů': 'u', 'ű': 'u', 'ų': 'u',
    'ν': 'v',
    'Ŵ': 'w', 'ŵ': 'w',
    'χ': 'x', 'ẋ': 'x',
    'у': 'y', 'ÿ': 'y', 'ý': 'y', 'ŷ': 'y',
    'ž': 'z', 'ź': 'z', 'ż': 'z', 'ẑ': 'z'
}


    domain = extract_domain(url)
    homoglyph_string = ''
    for char in domain:
        if char in homoglyphs.keys():
            homoglyph_string += homoglyphs[char]
        else:
          homoglyph_string += char
    return homoglyph_string

def extract_domain(url):
    import urllib.parse
    domain = urllib.parse.urlsplit(url).netloc
    return domain

def vowel_swap_string(url):
    vowels = 'aeiouAEIOU'
    swapped_url = ''
    for char in url:
        if char in vowels:
            if char.islower():
                swapped_url += char.upper()
            else:
                swapped_url += char.lower()
        else:
            swapped_url += char
    return swapped_url

#Frequency Encoding for tld and file_extension
def frequency_encoding(column):

    frequency_map = column.value_counts(normalize=True)
    encoded_column = column.map(frequency_map)
    return encoded_column
'''
data['tld'] = frequency_encoding(data['tld'])

data['file_extension'] = frequency_encoding(data['file_extension'])
'''
#Nominal Encoding for 'hyphenated_domain', 'url_homoglyphs','vowel_swap_urls'
def nominal_encoding_column(column_data):

    # Ensure column_data is converted to a pandas Series
    column_series = pd.Series(column_data)

    # Initialize LabelEncoder
    label_encoder = LabelEncoder()

    # Fit and transform the column
    encoded_column = label_encoder.fit_transform(column_series)

    return pd.Series(encoded_column, name=column_series.name)

'''
data['hyphenated_domain'] = nominal_encoding_column(data['hyphenated_domain'])
data['url_homoglyphs'] = nominal_encoding_column(data['url_homoglyphs'])
data['vowel_swap_urls'] = nominal_encoding_column(data['vowel_swap_urls'])
'''


def bool_to_int_column(df):
    if 'url' in df.columns and df['url'].dtype == bool:
        df['is_ip'] = df['is_ip'].astype(int)
        df['check_contains_exe'] = df['check_contains_exe'].astype(int)
        df['check_is_hashed'] = df['check_is_hashed'].astype(int)
        df['check_has_tld_in_subdomain'] = df['check_has_tld_in_subdomain'].astype(int)

    return df


def impute_with_mode(df):

    imputer = SimpleImputer(strategy='most_frequent')
    df_imputed = pd.DataFrame(imputer.fit_transform(df), columns=df.columns)
    return df_imputed



def preprocess_url(url):
    # Preprocess the URL
    url_length = len(url)
    is_ip = is_ip_address(url)
    contains_exe = check_contains_exe(url)
    digit_alphabet_ratio=check_digit_alphabet_ratio(url)
    specialchar_alphabet_ratio=get_specialchar_alphabet_ratio(url)
    uppercase_lowercase_ratio=get_uppercase_lowercase_ratio(url)
    domain_url_ratio=get_domain_url_ratio(url)
    numeric_char_count=get_numeric_char_count(url)
    english_letter_count=get_english_letter_count(url)
    has_shortening_service=check_has_shortening_service(url)
    special_char_count=get_special_char_count(url)
    count_dot=get_count_dot(url)
    count_semicolon=get_count_semicolon(url)
    count_underscore=get_count_underscore(url)
    count_question_mark=get_count_question_mark(url)
    count_hash=get_count_hash(url)
    count_equal=get_count_equal(url)
    count_percent_char=get_count_percent_char(url)
    count_ampersand=get_count_ampersand(url)
    count_dash=get_count_dash(url)
    count_delimiters=get_count_delimiters(url)
    count_at_char=get_count_at_char(url)
    count_tilde_char=get_count_tilde_char(url)
    count_double_slash=get_count_double_slash(url)
    is_hashed = check_is_hashed(url)
    extract_tld=get_extract_tld(url)
    dist_digit_alphabet=get_dist_digit_alphabet(url)
    has_https=get_has_https(url)
    extract_file_extension=get_extract_file_extension(url)
    has_tld_in_subdomain = check_has_tld_in_subdomain(url)
    has_tld_in_path = check_has_tld_in_path(url)
    has_disarranged_https = check_has_disarranged_https(url)
    hostname_length = get_hostname_length(url)
    path_length = get_path_length(url)
    query_length = get_query_length(url)
    has_anonymous_words = check_has_anonymous_words(url)
    has_www=check_has_www(url)
    has_ftp=check_has_ftp(url)
    has_js=check_has_js(url)
    has_files=check_has_files(url)
    has_css=check_has_css(url)
    is_domain_random=check_is_domain_random(url)
    count_sensitive_words=get_count_sensitive_words(url)
    shannon_entropy = check_shannon_entropy(url)
    hyphenated_domain = check_hyphenated_domain(url)
    url_homoglyphs = detect_homoglyphs(url)
    vowel_swap_urls = vowel_swap_string(url)


    # Convert the preprocessed URL to a DataFrame
    df = pd.DataFrame({
        
        'url_length': [url_length],
        'is_ip': [is_ip],
        'contains_exe': [contains_exe],
        'digit_alphabet_ratio':[digit_alphabet_ratio],
        'specialchar_alphabet_ratio':[specialchar_alphabet_ratio],
        'uppercase_lowercase_ratio':[uppercase_lowercase_ratio],
        'domain_url_ratio':[domain_url_ratio],
        'numeric_char_count':[numeric_char_count],
        'english_letter_count':[english_letter_count],
        'has_shortening_service':[has_shortening_service],
        'special_char_count':[special_char_count],
        'count_dot':[count_dot],
        'count_semicolon':[count_semicolon],
        'count_underscore':[count_underscore],
        'count_question_mark':[count_question_mark],
        'count_hash':[count_hash],
        'count_equal':[count_equal],
        'count_percent_char':[count_percent_char],
        'count_ampersand':[count_ampersand],
        'count_dash':[count_dash],
        'count_delimiters':[count_delimiters],
        'count_at_char':[count_at_char],
        'count_tilde_char':[count_tilde_char],
        'count_double_slash':[count_double_slash],
        'is_hashed': [is_hashed],
        'extract_tld':[extract_tld],
        'dist_digit_alphabet':[dist_digit_alphabet],
        'has_https':[has_https],
        'extract_file_extension':[extract_file_extension],
        'has_tld_in_subdomain': [has_tld_in_subdomain],
        'has_tld_in_path': [has_tld_in_path],
        'has_disarranged_https': [has_disarranged_https],
        'hostname_length': [hostname_length],
        'path_length': [path_length],
        'query_length': [query_length],
        'has_anonymous_words': [has_anonymous_words],
        'has_www':[has_www],
        'has_ftp':[has_ftp],
        'has_js':[has_js],
        'has_files':[has_files],
        'has_css':[has_css],
        'is_domain_random':[is_domain_random],
        'count_sensitive_words':[count_sensitive_words],
        'shannon_entropy': [shannon_entropy],
        'hyphenated_domain': [hyphenated_domain],
        'url_homoglyphs': [url_homoglyphs],
        'vowel_swap_urls': [vowel_swap_urls],

    })

    # Perform nominal encoding for 'hyphenated_domain', 'url_homoglyphs','vowel_swap_urls'
    df['hyphenated_domain'] = nominal_encoding_column(df['hyphenated_domain'])
    df['url_homoglyphs'] = nominal_encoding_column(df['url_homoglyphs'])
    df['vowel_swap_urls'] = nominal_encoding_column(df['vowel_swap_urls'])

    # Perform frequency encoding for 'tld' and 'file_extension'
    df['extract_tld'] = frequency_encoding(df['extract_tld'])
    df['extract_file_extension'] = frequency_encoding(df['extract_file_extension'])

    # Convert boolean columns to int
    df = bool_to_int_column(df)

    # Impute missing values with mode
    df = impute_with_mode(df)

    arr = df.to_numpy()
    return arr

