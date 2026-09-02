// Copyright (c) 2014-2022, The VeilRoot Project
// ... license header ...

#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <secp256k1.h>
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "misc_log_ex.h"
#include "bech32.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/tx_extra.h"
#include "common/bip340.h"

namespace domain_utils
{
    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------
    inline const uint64_t TIER_FEES[6] = {
        100000000000ULL,      // 0.1 VNS
        1000000000000ULL,     // 1 VNS
        10000000000000ULL,    // 10 VNS
        100000000000000ULL,   // 100 VNS
        1000000000000000ULL,  // 1000 VNS
        10000000000000000ULL  // 10000 VNS
    };

    inline constexpr uint64_t PREMIUM_TIER_FEE = 100000000000000000ULL; // 100,000 VNS

    // Custom TLV tags (must match those defined in the daemon)
    inline const uint8_t TX_EXTRA_TAG_DOMAIN_REGISTRATION = 0x06;   // domain registration data
    // TX_EXTRA_TAG_FINGERPRINT is already defined as 0x07 in tx_extra.h

        // ── Extension tier constants ────────────────────────────────
    inline constexpr uint8_t TIER_GENERIC    = 0;   // 0.1 VNS
    inline constexpr uint8_t TIER_AFFORDABLE = 1;   // 1 VNS
    inline constexpr uint8_t TIER_POPULAR    = 2;   // 10 VNS
    inline constexpr uint8_t TIER_PROFESSIONAL = 3; // 100 VNS
    inline constexpr uint8_t TIER_ENTERPRISE = 4;   // 1 000 VNS
    inline constexpr uint8_t TIER_SOVEREIGN  = 5;   // 10 000 VNS
    inline constexpr uint8_t TIER_PREMIUM    = 6;   // 100 000 VNS
    inline constexpr uint8_t TIER_BANNED     = 255; // forbidden

    // ── Tier 0 – Generic / open (0.1 VNS) ─
    inline const std::vector<std::string> GENERIC_EXTENSIONS = {
        "com", "org", "net", "info", "xyz", "blog", "site", "online",
        "me", "co", "shop", "club", "news", "media", "social", "world",
        "life", "fun", "space", "website", "press", "host", "cloud",
        "digital", "direct", "express", "free", "guru", "help", "live",
        "one", "plus", "rocks", "show", "software", "solutions", "support",
        "systems", "tips", "today", "tools", "training", "tv", "video",
        "vin", "vip", "work", "zone", "center", "company", "consulting",
        "design", "events", "expert", "global", "group", "guide",
        "institute", "international", "market", "money", "network",
        "partners", "photo", "pictures", "productions", "properties",
        "realty", "report", "services", "studio", "supply", "trading",
        "travel", "ventures", "vision", "watch", "web"
    };

    // ── Tier 1 – Affordable (1 VNS) ─
    inline const std::vector<std::string> AFFORDABLE_EXTENSIONS = {
        "biz", "pro", "io", "tv", "app", "dev", "agency", "consulting",
        "design", "studio", "expert", "partners", "ventures"
    };

    // ── Tier 2 – Popular / niche (10 VNS) ─
    inline const std::vector<std::string> POPULAR_EXTENSIONS = {
        "ai", "art", "music", "film", "gallery", "theater", "pub",
        "restaurant", "cafe", "bar", "fitness", "yoga", "health", "legal"
    };

    // ── Tier 3 – Premium professional (100 VNS) ─
    inline const std::vector<std::string> PREMIUM_EXTENSIONS = {
        "law", "doctor", "dentist", "accountant", "engineer", "university",
        "college", "academy", "school", "institute", "foundation",
        "charity", "ngo", "sport", "travel", "hotel", "insurance",
        "mortgage", "loans"
    };

    // ── Tier 4 – Enterprise / regulated (1 000 VNS) ─
    inline const std::vector<std::string> ENTERPRISE_EXTENSIONS = {
        "bank", "broker", "creditcard", "financial", "investments",
        "capital", "holdings", "enterprises", "industries", "corp",
        "inc", "ltd", "llc", "pharma", "biotech", "aerospace", "defense",
        "energy", "oil", "gas"
    };

    // ── Tier 5 – Sovereign / restricted (10 000 VNS) ─
    inline const std::vector<std::string> SOVEREIGN_EXTENSIONS = {
        // All country‑code TLDs (316 from IANA)
        "ac","ad","ae","af","ag","ai","al","am","ao","aq","ar","as","at",
        "au","aw","ax","az","ba","bb","bd","be","bf","bg","bh","bi","bj",
        "bl","bm","bn","bo","bq","br","bs","bt","bv","bw","by","bz","ca",
        "cc","cd","cf","cg","ch","ci","ck","cl","cm","cn","co","cr","cu",
        "cv","cw","cx","cy","cz","de","dj","dk","dm","do","dz","ec","ee",
        "eg","er","es","et","eu","fi","fj","fk","fm","fo","fr","ga","gd",
        "ge","gf","gg","gh","gi","gl","gm","gn","gp","gq","gr","gs","gt",
        "gu","gw","gy","hk","hm","hn","hr","ht","hu","id","ie","il","im",
        "in","io","iq","ir","is","it","je","jm","jo","jp","ke","kg","kh",
        "ki","km","kn","kp","kr","kw","ky","kz","la","lb","lc","li","lk",
        "lr","ls","lt","lu","lv","ly","ma","mc","md","me","mg","mh","mk",
        "ml","mm","mn","mo","mp","mq","mr","ms","mt","mu","mv","mw","mx",
        "my","mz","na","nc","ne","nf","ng","ni","nl","no","np","nr","nu",
        "nz","om","pa","pe","pf","pg","ph","pk","pl","pm","pn","pr","ps",
        "pt","pw","py","qa","re","ro","rs","ru","rw","sa","sb","sc","sd",
        "se","sg","sh","si","sj","sk","sl","sm","sn","so","sr","ss","st",
        "sv","sx","sy","sz","tc","td","tf","tg","th","tj","tk","tl","tm",
        "tn","to","tr","tt","tv","tw","tz","ua","ug","uk","us","uy","uz",
        "va","vc","ve","vg","vi","vn","vu","wf","ws","ye","yt","za","zm","zw",

        // ICANN‑restricted / government
        "gov","edu","mil","int","parliament","congress","senate","army",
        "navy","airforce","police","fbi","cia","nsa","court","justice",
        "diplomacy","embassy","consulate","minister","ministry","department",
        "federal","state","municipal","city","county"
    };

    // ── Banned extensions ─
    inline const std::vector<std::string> BANNED_EXTENSIONS = {
        "example","test","invalid","localhost","onion","arpa","root",
        "corp","home","mail","nato","icann","iana","internic",
        "whois","dns","ddns","dyndns","noip","afraid","freedns",
        "zoneedit","cloudns","easydns"
    };

    // ── Banned terms (never allowed as label or extension) ─────
    // Morally abhorrent / illegal
    inline const std::vector<std::string> BANNED_ABHORRENT_TERMS = {
        "rape","rapes","rapist","raping","raped","rap3","rap3d","r4pe","r4p3",
        "murder","murders","murderer","murdering","murd3r","murd3rs",
        "pedophile","pedophilia","pedo","pedofile","paedophile","paedophilia",
        "childporn","childabuse","childpornography","lolita","preteen",
        "abuse","abuser","abusing","abus3","abus3r","abus3d",
        "gore","gory","g0re","g0ry","torture","tortur3","t0rture",
        "necrophilia","necrophile","necro","necrophil","necrophiliac",
        "suicide","suicidal","suicid3","suicid4l","kill","killyourself",
        "kys","hangyourself","selfharm","selfmutilation",
        "incest","inc3st","incestuous","bestiality","beastiality","zoophilia",
        "fisting","fistfucking","scat","scatology","watersports","pissplay",
        "snuff","snufffilm","snuffporn","snuffmovie",
        "kidnapping","kidnap","kidnapper","kidn4p","abduction","abduct",
        "terrorist","terrorism","terror","t3rror","t3rrorist","bombmaking",
        "cannabis","cocaine","heroin","methamphetamine","meth","lsd",
        "ecstasy","mdma","fentanyl","opioid","opium","crack","ketamine",
        "amphetamines","marijuana","weed","hashish","hash","thc",
        "pornography","porn","pron","pr0n","p0rn","xxx","adultvideo",
        "hardcore","softcore","teensex","milf","bdsm","bondage","sadomasochism",
        "domination","submission","swinger","swinging","hooker","hookers",
        "prostitute","prostitution","escortservice","brothel","whore",
        "whorehouse","stripclub","stripper","lapdance","sexwork","sexworker",
        "sexslave","sextrafficking","humantrafficking","trafficking"
    };

    // Project‑reserved (cannot be registered unless DAO votes otherwise)
    inline const std::vector<std::string> PROJECT_RESERVED_TERMS = {
        "veilroot","veil","root","vns","veilrootdao","vnsdao","veilnet",
        "veilchain","veilname","veilrootname","veilrootnamesystem",
        "veilrootprotocol","veilrootdns","veilrootdomain","veilrootdomains"
    };

    // ── Premium label categories (all map to TIER_SOVEREIGN) ─
    inline const std::vector<std::string> BIG_TECH_LABELS = {
        "apple","appleinc","google","alphabet","youtube","android","chrome",
        "microsoft","windows","azure","office","linkedin","github","skype",
        "amazon","aws","kindle","audible","twitch","imdb","meta","facebook",
        "instagram","whatsapp","messenger","threads","oculus","x","twitter",
        "tesla","spacex","starlink","palantir","openai","anthropic","deepmind",
        "nvidia","intel","amd","qualcomm","broadcom","cisco","oracle","sap",
        "salesforce","ibm","hp","dell","sony","panasonic","samsung","lg",
        "xiaomi","huawei","zte","lenovo","asus","acer","logitech","razer",
        "tiktok","bytedance","snapchat","pinterest","reddit","spotify",
        "netflix","hulu","disney","warner","paramount","hbo","peacock",
        "tencent","alibaba","baidu","naver","kakao","yandex","mailru","vk",
        "cloudflare"
    };

    inline const std::vector<std::string> FINANCE_LABELS = {
        // Global banks
        "goldmansachs","jpmorgan","jpmorganchase","morganstanley",
        "bankofamerica","bofa","citigroup","citi","wellsfargo","barclays",
        "hsbc","ubs","creditsuisse","deutschebank","bnpparibas",
        "societegenerale","commerzbank","unicredit","intesa","santander",
        "bbva","ing","abnamro","nordea","dnb","swedbank","seb",
        "standardchartered","westpac","nab","anz","cba","dbs","ocbc",
        "uob","mizuho","mitsubishiufj","smbc","nomura","daiwa",
        "icbc","chinaconstructionbank","agriculturalbankofchina",
        "bankofchina","bankofcommunications","pingan",
        "sberbank","vtb","gazprombank","alfabank",
        "itau","bradesco","bancodobrasil","santanderbrasil",
        // Asset managers
        "blackrock","vanguard","fidelity","statestreet","pimco",
        "capitalgroup","troweprice","franklin","templeton","invesco",
        "janie","wellington","putnam","berkshirehathaway",
        // Hedge funds / trading
        "citadel","point72","millennium","bragg","renaissance",
        "twosigma","deshaw","jump","virtu","susquehanna",
        // Insurance
        "aig","prudential","metlife","allstate","statefarm","progressive",
        "geico","libertymutual","guardian","principal","hartford",
        "travelers","nationwide","usaa","axa","allianz","generali","zurich",
        "munichre","swissre","berkshire","hathaway",
        // Payments / cards
        "visa","mastercard","americanexpress","paypal","venmo","stripe",
        "square","block","adyen","worldpay","fiserv","fis","globalpayments",
        // Fintech / exchanges (centralised crypto & surveillance enablers)
        "binance","coinbase","kraken","gemini","bitfinex","bitstamp",
        "huobi","okx","bybit","kucoin","gateio","cryptocom","robinhood",
        "revolut","wise","n26","nubank","chime","sofi",
        // Surveillance / compliance in finance
        "chainalysis","elliptic","ciphertrace","trm","compilatio",
        "refinitiv","worldcheck","dowjones","lexisnexis","relx",
        "experian","equifax","transunion",
        // International finance bodies
        "bis","worldbank","imf","wef","fsb","iosco","basel","fatf",
        "ecb","federalreserve","bankofengland","boj","pbc","boe",
        "swift","chips"
    };

    inline const std::vector<std::string> GOVERNMENT_KEYWORDS = {
        // English
        "government","ministry","minister","department","federal","national",
        "state","provincial","municipal","city","county","township","borough",
        "parish","canton","agency","administration","authority","commission",
        "committee","council","board","assembly","parliament","congress",
        "senate","house","chamber","court","justice","police","sheriff",
        "marshal","constable","trooper","patrol","investigation","fbi","cia",
        "nsa","dia","nga","nro","dea","atf","ice","cbp","tss","secretservice",
        "intelligence","counterterrorism","homeland","security","defense",
        "armedforces","army","navy","airforce","marines","coastguard",
        "militia","guard","reserve","veteran","affairs",
        "gchq","fiveeyes","fisa",
        // Spanish
        "gobierno","estado","nacional","provincial","municipal","ciudad",
        "condado","departamento","ministerio","oficina","agencia",
        "administracion","comision","comite","consejo","asamblea",
        "parlamento","congreso","senado","camara","corte","justicia",
        "policia","fiscal","juez","investigacion","inteligencia",
        "seguridad","defensa","fuerzasarmadas","ejercito","armada",
        "fuerzaaerea","marina","guardiacivil",
        // French
        "gouvernement","etat","national","provincial","municipal","ville",
        "departement","ministere","bureau","agence","administration",
        "commission","comite","conseil","assemblee","parlement","congres",
        "senat","chambre","cour","justice","police","enquete",
        "renseignement","securite","defense","armees","armee","marine",
        "garde",
        // German
        "regierung","staat","bundes","landes","kreis","stadt","gemeinde",
        "ministerium","amt","behoerde","verwaltung","kommission","ausschuss",
        "rat","parlament","bundestag","senat","gericht","justiz","polizei",
        "ermittlung","geheimdienst","nachrichtendienst","sicherheit",
        "verteidigung","streitkraefte","armee","marine","luftwaffe",
        // Russian
        "правительство","государство","федеральный","региональный",
        "муниципальный","город","район","департамент","министерство",
        "ведомство","служба","комиссия","комитет","совет","парламент",
        "сенат","суд","юстиция","полиция","расследование","разведка",
        "безопасность","оборона","вооруженныесилы","армия","флот",
        // Chinese (simplified)
        "政府","国务院","国家","部","部门","省","市","县","区","警察",
        "军队","国防","安全","情报","法院","检察院",
        // Arabic
        "حكومة","وزارة","وزير","دولة","شرطة","جيش","أمن","مخابرات",
        "قضاء","محكمة","برلمان","مجلس"
    };

    inline const std::vector<std::string> INTERNATIONAL_BODIES = {
        "un","unitednations","undp","unicef","unesco","who","ilo","imf",
        "worldbank","wto","oecd","nato","eu","europeanunion","ecb",
        "africanunion","asean","mercosur","g7","g20","brics","interpol",
        "icrc","redcross","redcrescent","wef","bis","fatf","iosco",
        "icann","iana","iso","itu","upu","wipo","wmo","iaea","opcw",
        "icc","icj","pca","unhcr","unrwa","wfp","fao","ifad","unido",
        "unctad","unep","unfccc","unhabitat","unwomen","unfpa","iom",
        "ieee","w3c","freedomhouse","article19","eff","opensociety",
        "mozilla","wikimedia","isoc","privacyinternational","aclu"
    };

    inline const std::vector<std::string> DEFENCE_CONTRACTORS = {
        "lockheedmartin","raytheon","northropgrumman","generaldynamics",
        "boeing","baesystems","thales","leonardo","saab","airbus",
        "elbit","cobham","meggitt","ultra","l3harris","harris","leidos",
        "caci","mitre","sra","boozallen","anduril","palantir","epirus",
        "shieldai","hawk","dedrone","clearviewai","hikvision","dahua",
        "axon","cellebrite","nsogroup","finfisher","gammagroup",
        "blackcube","intellxa","k2integrity"
    };

    inline const std::vector<std::string> TELECOM_MEDIA_LABELS = {
        "at&t","att","verizon","tmobile","sprint","comcast","charter",
        "cox","dish","vodafone","orange","telefonica","deutschetelekom",
        "bt","sky","ntt","kddi","softbank","singtel","telstra","rogers",
        "bell","telenor","telia","swisscom","nokia","ericsson","huawei",
        "zte","disney","warner","nbc","cbs","abc","bbc","cnn","fox",
        "bloomberg","reuters","ap","afp","nytimes","wsj","news","sinclair",
        "viacom","discovery","amc","aenetworks","lionsgate","mgm"
    };

    // ── Helper functions (all replaced) ────────────────────────

    // Build the combined extension‑to‑tier map once
    inline const std::unordered_map<std::string, uint8_t>& get_extension_tier_map()
    {
        static const std::unordered_map<std::string, uint8_t> map = []() {
            std::unordered_map<std::string, uint8_t> m;
            for (const auto& ext : GENERIC_EXTENSIONS)     m[ext] = TIER_GENERIC;
            for (const auto& ext : AFFORDABLE_EXTENSIONS)  m[ext] = TIER_AFFORDABLE;
            for (const auto& ext : POPULAR_EXTENSIONS)     m[ext] = TIER_POPULAR;
            for (const auto& ext : PREMIUM_EXTENSIONS)     m[ext] = TIER_PROFESSIONAL;
            for (const auto& ext : ENTERPRISE_EXTENSIONS)  m[ext] = TIER_ENTERPRISE;
            for (const auto& ext : SOVEREIGN_EXTENSIONS)   m[ext] = TIER_SOVEREIGN;
            for (const auto& ext : BANNED_EXTENSIONS)      m[ext] = TIER_BANNED;
            return m;
        }();
        return map;
    }

    // Get the fee tier for an extension (default = TIER_PREMIUM)
    inline uint8_t get_tier_for_extension(const std::string& extension) {
        const auto& map = get_extension_tier_map();
        auto it = map.find(extension);
        return (it != map.end()) ? it->second : TIER_PREMIUM;
    }

    // Check if an extension is banned
    inline bool is_extension_locked(const std::string& extension) {
        const auto& map = get_extension_tier_map();
        auto it = map.find(extension);
        return it != map.end() && it->second == TIER_BANNED;
    }

    // Build the complete banned‑label set once
    inline const std::unordered_set<std::string>& get_banned_labels()
    {
        static const std::unordered_set<std::string> set = []() {
            std::unordered_set<std::string> s;
            auto add = [&](const std::vector<std::string>& v) {
                s.insert(v.begin(), v.end());
            };
            add(BANNED_ABHORRENT_TERMS);
            add(PROJECT_RESERVED_TERMS);
            return s;
        }();
        return set;
    }

    // Returns true if the given label (or extension) is banned
    inline bool is_label_banned(const std::string& label)
    {
        const auto& set = get_banned_labels();
        return set.count(label) > 0;
    }

    // ── Premium label detection ─────────────────────────────────
    inline const std::unordered_set<std::string>& get_premium_labels()
    {
        static const std::unordered_set<std::string> set = []() {
            std::unordered_set<std::string> s;
            auto add = [&](const std::vector<std::string>& v) {
                s.insert(v.begin(), v.end());
            };
            add(BIG_TECH_LABELS);
            add(FINANCE_LABELS);
            add(GOVERNMENT_KEYWORDS);
            add(INTERNATIONAL_BODIES);
            add(DEFENCE_CONTRACTORS);
            add(TELECOM_MEDIA_LABELS);
            return s;
        }();
        return set;
    }

    // Returns TIER_SOVEREIGN if the label is premium, otherwise 0
    inline uint8_t get_label_tier(const std::string& label)
    {
        const auto& set = get_premium_labels();
        return (set.count(label) > 0) ? TIER_SOVEREIGN : 0;
    }

    // Old helper kept for compatibility
    inline bool is_premium_label(const std::string& label) {
        return get_label_tier(label) == TIER_SOVEREIGN;
    }

    inline uint64_t get_required_fee(uint8_t tier) {
        if (tier == TIER_PREMIUM)
            return PREMIUM_TIER_FEE;
        return (tier < 6) ? TIER_FEES[tier] : 0;
    }

    inline uint64_t get_required_fee_for_extension(const std::string& extension) {
        return get_required_fee(get_tier_for_extension(extension));
    }

    // ── Legacy conversion helpers (preserved from earlier version) ─
    inline std::vector<uint8_t> convert_bits(const std::vector<unsigned char>& in, size_t in_bits, size_t out_bits, bool pad = true)
    {
        std::vector<uint8_t> ret;
        uint32_t acc = 0;
        size_t bits = 0;
        const size_t maxv = (1 << out_bits) - 1;
        for (size_t i = 0; i < in.size(); ++i) {
            uint32_t val = in[i];
            if ((val >> in_bits) != 0) return {};
            acc = (acc << in_bits) | val;
            bits += in_bits;
            while (bits >= out_bits) {
                bits -= out_bits;
                ret.push_back((acc >> bits) & maxv);
            }
        }
        if (pad && bits > 0) {
            ret.push_back((acc << (out_bits - bits)) & maxv);
        }
        return ret;
    }

    // Conversion from nsec1/npub1 to raw keys
    inline bool nsec_to_private_key(const std::string& nsec, crypto::secret_key& skey)
    {
        if (nsec.size() < 8 || nsec.substr(0, 4) != "nsec") return false;
        bech32::Encoding enc;
        std::string hrp;
        std::vector<uint8_t> data5;
        std::tie(enc, hrp, data5) = bech32::Decode(nsec);
        if (enc != bech32::Encoding::BECH32 || hrp != "nsec") return false;
        std::vector<uint8_t> raw = convert_bits(data5, 5, 8, false);
        if (raw.size() == 32) {
            memcpy(skey.data, raw.data(), 32);
        } else if (raw.size() == 33 && raw[0] == 0) {
            memcpy(skey.data, raw.data() + 1, 32);
        } else {
            return false;
        }
        return true;
    }

    inline bool npub_to_public_key(const std::string& npub, crypto::public_key& pkey)
    {
        if (npub.size() < 8 || npub.substr(0, 4) != "npub") return false;
        bech32::Encoding enc;
        std::string hrp;
        std::vector<uint8_t> data5;
        std::tie(enc, hrp, data5) = bech32::Decode(npub);
        if (enc != bech32::Encoding::BECH32 || hrp != "npub") return false;
        std::vector<uint8_t> raw = convert_bits(data5, 5, 8, false);
        if (raw.size() == 32) {
            memcpy(pkey.data, raw.data(), 32);
            return true;
        } else if (raw.size() == 33 && raw[0] == 0) {
            memcpy(pkey.data, raw.data() + 1, 32);
            return true;
        }
        return false;
    }

    inline bool nostr_seed_to_secret_key(const crypto::secret_key& seed, crypto::secret_key& secret_scalar)
    {
        memcpy(secret_scalar.data, seed.data, sizeof(seed.data));
        sc_reduce32(reinterpret_cast<unsigned char*>(secret_scalar.data));
        return true;
    }

    // Domain name validation helpers
    inline bool validate_domain_name_format(const std::string& domain) {
        size_t dotdot = domain.find("..");
        if (dotdot == std::string::npos || dotdot == 0 || dotdot + 2 >= domain.size())
            return false;
        std::string label = domain.substr(0, dotdot);
        std::string ext = domain.substr(dotdot + 2);
        if (label.empty() || ext.empty() || label.size() > 32 || ext.size() > 15 || domain.size() > 49)
            return false;
        auto valid_label_char = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '-';
        };
        auto valid_ext_char = [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        };
        if (!std::all_of(label.begin(), label.end(), valid_label_char) ||
            !std::all_of(ext.begin(), ext.end(), valid_ext_char))
            return false;
        bool has_letter = false;
        for (char c : label) if (std::isalpha(c)) { has_letter = true; break; }
        for (char c : ext)   if (std::isalpha(c)) { has_letter = true; break; }
        return has_letter;
    }

    inline bool parse_vns_domain(const std::string& domain, std::string& label, std::string& extension) {
        size_t dotdot = domain.find("..");
        if (dotdot == std::string::npos) return false;
        label = domain.substr(0, dotdot);
        extension = domain.substr(dotdot + 2);
        return !label.empty() && !extension.empty();
    }

    // Canonical VNS extension: lowercase alphanumeric only.
    // No dots, hyphens, underscores or other punctuation.
    inline bool is_valid_vns_extension(const std::string& extension) {
        if (extension.empty() || extension.size() > 15)
            return false;
        for (char c : extension)
        {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
                return false;
        }
        return true;
    }

    inline std::string normalize_vns_extension(const std::string& extension) {
        std::string out = extension;
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (!is_valid_vns_extension(out))
            return "";
        return out;
    }

    // Canonical VNS label: lowercase alphanumeric and hyphen.
    inline bool is_valid_vns_label(const std::string& label) {
        if (label.empty() || label.size() > 32)
            return false;
        for (char c : label)
        {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-')
                return false;
        }
        return true;
    }

    inline std::string normalize_vns_label(const std::string& label) {
        std::string out = label;
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (!is_valid_vns_label(out))
            return "";
        return out;
    }

        // Canonical normalization function for VNS domain names.
    // Converts to lowercase, trims leading/trailing whitespace,
    // validates exact label..extension grammar, and returns canonical string.
    inline std::string normalize_vns_domain(const std::string& domain)
    {
        std::string trimmed = domain;
        auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
        auto first = std::find_if(trimmed.begin(), trimmed.end(), not_space);
        auto last = std::find_if(trimmed.rbegin(), trimmed.rend(), not_space).base();
        if (first >= last) return "";
        trimmed = std::string(first, last);

        std::transform(trimmed.begin(), trimmed.end(), trimmed.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        if (!validate_domain_name_format(trimmed))
            return "";

        return trimmed;
    }

    // Legacy extension helpers (still called by other functions)
    inline bool is_valid_extension(const std::string& extension) {
        if (is_extension_locked(extension)) return false;
        if (extension.empty() || extension.size() > 15) return false;
        for (char c : extension)
            if (!std::isalnum(c) && c != '-') return false;
        bool has_letter = false;
        for (char c : extension) if (std::isalpha(c)) { has_letter = true; break; }
        return has_letter;
    }

    inline std::vector<std::string> get_all_extensions() {
        std::vector<std::string> exts;
        const auto& map = get_extension_tier_map();
        for (const auto& pair : map) exts.push_back(pair.first);
        // Fallback defaults (these are already in GENERIC_EXTENSIONS, but keep for compatibility)
        std::vector<std::string> defaults = {"free", "art", "defi"};
        for (const auto& ext : defaults)
            if (std::find(exts.begin(), exts.end(), ext) == exts.end())
                exts.push_back(ext);
        return exts;
    }

    // ------------------------------------------------------------------
    // tx_extra builders using separate TLVs (0x07 for fingerprint, 0x06 for domain data)
    // ------------------------------------------------------------------
    inline std::vector<uint8_t> build_registration_extra(
        const std::string& domain_name,
        uint8_t fee_tier,
        const std::array<unsigned char, 33>& registrant_key,
        const crypto::hash& genesis_fingerprint,
        const std::array<std::string, 3>& relay_urls = {})
    {
        std::vector<uint8_t> extra;

        std::vector<uint8_t> payload;
        const char MAGIC[] = "DOMAIN_REG";
        payload.insert(payload.end(), MAGIC, MAGIC + strlen(MAGIC));

        auto append_tlv = [&](uint8_t type, const void* data, size_t len) {
            payload.push_back(type);
            payload.push_back(static_cast<uint8_t>(len));
            const uint8_t* bytes = static_cast<const uint8_t*>(data);
            payload.insert(payload.end(), bytes, bytes + len);
        };

        append_tlv(0x01, domain_name.data(), domain_name.size());
        append_tlv(0x02, &fee_tier, 1);
        append_tlv(0x03, registrant_key.data(), registrant_key.size());
        append_tlv(0x04, &genesis_fingerprint, sizeof(genesis_fingerprint));

        static constexpr uint8_t relay_tags[3] = {0x06, 0x07, 0x08};
        for (size_t i = 0; i < relay_urls.size(); ++i)
        {
            const std::string& url = relay_urls[i];
            if (url.empty())
                continue;

            if (url.size() > 255)
                return {};

            append_tlv(relay_tags[i], url.data(), url.size());
        }

        payload.push_back(0x00);

        if (payload.size() > 255)
            return {};

        extra.push_back(0x02);
        extra.push_back(static_cast<uint8_t>(payload.size()));
        extra.insert(extra.end(), payload.begin(), payload.end());

        return extra;
    }

    inline std::vector<uint8_t> build_update_extra(
        const std::string& domain_name,
        const boost::optional<std::array<unsigned char, 33>>& new_owner_key,
        const boost::optional<std::array<std::string, 3>>& new_relay_set,
        const std::array<unsigned char, 64>& signature)
    {
        std::vector<uint8_t> payload;
        const char MAGIC[] = "DOMAIN_UPDATE";
        payload.insert(payload.end(), MAGIC, MAGIC + strlen(MAGIC));

        auto append_tlv = [&](uint8_t type, const void* data, size_t len) {
            payload.push_back(type);
            payload.push_back(static_cast<uint8_t>(len));
            const uint8_t* bytes = static_cast<const uint8_t*>(data);
            payload.insert(payload.end(), bytes, bytes + len);
        };

        append_tlv(0x01, domain_name.data(), domain_name.size());

        if (new_owner_key) {
            append_tlv(0x02, new_owner_key->data(), new_owner_key->size());
        }

        if (new_relay_set) {
            size_t count = 0;
            for (const auto& url : *new_relay_set)
                if (!url.empty()) ++count;

            if (count > 0 && count <= 3)
            {
                std::vector<uint8_t> relay_data;
                relay_data.push_back(static_cast<uint8_t>(count));

                for (const auto& url : *new_relay_set)
                {
                    if (url.empty())
                        continue;

                    if (url.size() > 255)
                        return {};

                    relay_data.push_back(static_cast<uint8_t>(url.size()));
                    relay_data.insert(relay_data.end(), url.begin(), url.end());
                }

                append_tlv(0x10, relay_data.data(), relay_data.size());
            }
        }

        append_tlv(0x04, signature.data(), signature.size());

        payload.push_back(0x00);

        if (payload.size() > 255)
            return {};

        std::vector<uint8_t> extra;
        extra.push_back(0x02);
        extra.push_back(static_cast<uint8_t>(payload.size()));
        extra.insert(extra.end(), payload.begin(), payload.end());
        return extra;
    }

    inline std::vector<uint8_t> build_transfer_extra(
        const std::string& domain_name,
        const crypto::public_key& new_owner_key,
        const std::array<unsigned char, 64>& signature)
    {
        std::vector<uint8_t> payload;
        const char MAGIC[] = "DOMAIN_XFER";
        payload.insert(payload.end(), MAGIC, MAGIC + strlen(MAGIC));

        auto append_tlv = [&](uint8_t type, const void* data, size_t len) {
            payload.push_back(type);
            payload.push_back(static_cast<uint8_t>(len));
            const uint8_t* bytes = static_cast<const uint8_t*>(data);
            payload.insert(payload.end(), bytes, bytes + len);
        };

        append_tlv(0x01, domain_name.data(), domain_name.size());
        append_tlv(0x05, &new_owner_key, sizeof(new_owner_key));
        append_tlv(0x04, signature.data(), signature.size());
        payload.push_back(0x00);

        if (payload.size() > 255) return {};

        std::vector<uint8_t> extra;
        extra.push_back(0x02); // TX_EXTRA_TAG_NONCE
        extra.push_back(static_cast<uint8_t>(payload.size()));
        extra.insert(extra.end(), payload.begin(), payload.end());
        return extra;
    }

    // ------------------------------------------------------------
    // SHA256 helper (uses OpenSSL)
    // ------------------------------------------------------------
    inline std::string sha256(const std::string& input)
    {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, input.data(), input.size());
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);
        std::stringstream ss;
        for (unsigned int i = 0; i < hash_len; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        return ss.str();
    }

    // ------------------------------------------------------------
    // Build and sign a Nostr heartbeat event (kind 30001)
    // Returns the signed event JSON string, or empty on failure.
    // ------------------------------------------------------------
    inline std::string build_nostr_heartbeat_event(
        const std::string& domain_name,
        const std::string& fingerprint_hex,
        const std::string& block_hash_hex,
        const std::string& proof_block_hash_hex,
        uint64_t leaf_index,
        const std::vector<std::string>& sibling_hashes_hex,
        const unsigned char* private_key_32,
        const std::string& relay_url,
        uint64_t heartbeat_block_height = 0,
        uint64_t heartbeat_count = 0)
    {
        // Build tags array as JSON strings
        std::stringstream tags;
        tags << "[";
        tags << "[\"d\",\"" << domain_name << "\"],";
        tags << "[\"fingerprint\",\"" << fingerprint_hex << "\"],";
        tags << "[\"block_hash\",\"" << proof_block_hash_hex << "\"],";
        tags << "[\"leaf_index\",\"" << leaf_index << "\"],";
        tags << "[\"heartbeat_height\",\"" << heartbeat_block_height << "\"],";
        tags << "[\"heartbeat_count\",\"" << heartbeat_count << "\"],";
        tags << "[\"sibling_path\",\"";
        for (size_t i = 0; i < sibling_hashes_hex.size(); ++i) {
            if (i > 0) tags << ",";
            tags << sibling_hashes_hex[i];
        }
        tags << "\"]";
        tags << "]";

        // Content: simple string
        std::string content = "\"heartbeat\"";

        // Created timestamp
        uint64_t created_at = std::time(nullptr);

        // Build the event object with alphabetical key order
        // Keys: content, created_at, kind, pubkey, tags
        std::stringstream event_stream;
        event_stream << "{\"content\":" << content << ",";
        event_stream << "\"created_at\":" << created_at << ",";
        event_stream << "\"kind\":30001,";
        event_stream << "\"pubkey\":\"\",";
        event_stream << "\"tags\":" << tags.str() << "}";
        std::string event_no_id = event_stream.str();

        // Derive public key from private key (BIP340)
        secp256k1_context* secp = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!secp) return "";
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(secp, &pubkey, private_key_32)) {
            secp256k1_context_destroy(secp);
            return "";
        }
        unsigned char pubkey_compressed[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(secp, pubkey_compressed, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
        secp256k1_context_destroy(secp);

        // pubkey hex (x-only, 32 bytes)
        std::stringstream pk_hex;
        for (int i = 1; i < 33; ++i)
            pk_hex << std::hex << std::setw(2) << std::setfill('0') << (int)pubkey_compressed[i];
        std::string pubkey_hex = pk_hex.str();

        // NIP-01 canonical serialization used for event IDs
        std::stringstream nostr_serialized;

        nostr_serialized
        << "[0,"
        << "\"" << pubkey_hex << "\","
        << created_at << ","
        << "30001,"
        << tags.str() << ","
        << "\"heartbeat\""
        << "]";

        std::string event_to_hash = nostr_serialized.str();


        // Compute Nostr event ID
        std::string id_hex = sha256(event_to_hash);

        // Convert id_hex to binary (32 bytes)
        unsigned char id_bin[32];
        for (size_t i = 0; i < 32; ++i) {
            std::string byte_str = id_hex.substr(i*2, 2);
            id_bin[i] = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        }

        // Sign the id with BIP340 (raw private key)
        unsigned char sig[64];
        if (!bip340::sign(private_key_32, id_bin, sig))
            return "";

        // Convert signature to hex
        std::stringstream sig_hex;
        for (int i = 0; i < 64; ++i)
            sig_hex << std::hex << std::setw(2) << std::setfill('0') << (int)sig[i];

        // Build final signed event JSON with alphabetical key order
        std::stringstream signed_event;
        signed_event << "{\"id\":\"" << id_hex << "\",";
        signed_event << "\"content\":" << content << ",";
        signed_event << "\"created_at\":" << created_at << ",";
        signed_event << "\"kind\":30001,";
        signed_event << "\"pubkey\":\"" << pubkey_hex << "\",";
        signed_event << "\"tags\":" << tags.str() << ",";
        signed_event << "\"sig\":\"" << sig_hex.str() << "\"}";
        return signed_event.str();
    }

} // namespace domain_utils