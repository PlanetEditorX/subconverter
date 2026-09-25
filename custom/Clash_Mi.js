function main(config) {

  // ================================================================
  // Clash Mi / Mihomo Perfect-Rules v1.7
  //
  // Architecture:
  //
  //   Airport Subscription
  //          ↓
  //   Preserve Airport Basic Groups
  //          ↓
  //   Dynamic Region Groups
  //          ↓
  //   Perfect-Rules Service Groups
  //          ↓
  //   Remote Rule Providers
  //
  // JS:
  //   Responsible for configuration architecture
  //
  // GitHub Rule Providers:
  //   Responsible for actual routing rules
  //
  // Network Test:
  //   Follow airport's default manual selector
  //
  // ================================================================


  // ================================================================
  // 1. Basic configuration
  // ================================================================

  config["mixed-port"] = 7890;

  config["mode"] = "rule";

  config["unified-delay"] = true;

  config["tcp-concurrent"] = true;

  config["log-level"] = "error";

  config["ipv6"] = false;

  config["allow-lan"] = false;

  config["find-process-mode"] = "always";

  config["keep-alive-interval"] = 30;

  config["keep-alive-idle"] = 30;

  config["disable-keep-alive"] = false;


  // ================================================================
  // 2. Profile
  // ================================================================

  config["profile"] = {

    "store-selected": true,

    "store-fake-ip": true

  };


  // ================================================================
  // 3. DNS
  // ================================================================

  config["dns"] = {

    "enable": true,

    "listen": "0.0.0.0:53",

    "prefer-h3": false,

    "ipv6": false,

    "enhanced-mode": "fake-ip",

    "fake-ip-range": "172.19.0.1/16",

    "fake-ip-filter-mode": "blacklist",

    "respect-rules": true,

    "fake-ip-filter": [

      "+.lan",
      "+.local",
      "+.localhost",
      "+.home.arpa",

      "time.*.com",
      "time.*.gov",
      "pool.ntp.org",

      "+.push.apple.com",

      "mesu.apple.com",
      "swscan.apple.com",

      "captive.apple.com",

      "connectivitycheck.gstatic.com",

      "connectivitycheck.android.com",

      "www.msftconnecttest.com",

      "www.msftncsi.com"

    ],

    "default-nameserver": [

      "223.5.5.5",
      "119.29.29.29"

    ],

    "nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "nameserver-policy": {

      "geosite:cn": [

        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"

      ],

      "geosite:private": [

        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"

      ],

      "geolocation-!cn": [

        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query"

      ]

    },

    "proxy-server-nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "direct-nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "fallback": [

      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"

    ],

    "fallback-filter": {

      "geoip": true,

      "geoip-code": "CN",

      "geosite": [

        "gfw"

      ],

      "domain": [

        "+.google.com",
        "+.googleapis.com",
        "+.googlevideo.com",
        "+.youtube.com",
        "+.github.com",
        "+.openai.com",
        "+.chatgpt.com",
        "+.anthropic.com",
        "+.claude.ai"

      ]

    }

  };


  // ================================================================
  // 4. TUN
  // ================================================================

  config["tun"] = {

    "enable": true,

    "device": "Clash Mi",

    "stack": "gvisor",

    "dns-hijack": [

      "0.0.0.0:53"

    ],

    "auto-route": true,

    "auto-detect-interface": false,

    "strict-route": true,

    "mtu": 1280,

    "inet4-address": [

      "172.19.0.1/30"

    ],

    "auto-redirect": false,

    "disable-icmp-forwarding": true

  };


  // ================================================================
  // 5. Sniffer
  // ================================================================

  config["sniffer"] = {

    "enable": true,

    "parse-pure-ip": true,

    "force-dns-mapping": true,

    "override-destination": true,

    "sniff": {

      "HTTP": {

        "ports": [

          80,
          "8080-8880"

        ]

      },

      "TLS": {

        "ports": [

          443,
          8443

        ]

      },

      "QUIC": {

        "ports": [

          443,
          8443

        ]

      }

    },

    "skip-domain": [

      "+.push.apple.com",
      "+.mijia.cloud"

    ]

  };


  // ================================================================
  // 6. NTP
  // ================================================================

  config["ntp"] = {

    "enable": true,

    "write-to-system": false,

    "server": "time.apple.com",

    "port": 123,

    "interval": 30

  };


  // ================================================================
  // 7. Original airport proxies
  // ================================================================

  var originalProxies = Array.isArray(config["proxies"])
    ? config["proxies"]
    : [];


  var proxyNames = [];

  originalProxies.forEach(function(proxy) {

    if (proxy && proxy.name) {

      proxyNames.push(proxy.name);

    }

  });


  // ================================================================
  // 8. Original airport proxy groups
  // ================================================================

  var originalGroups = Array.isArray(config["proxy-groups"])
    ? config["proxy-groups"]
    : [];


  // ================================================================
  // 9. Perfect-Rules icon CDN
  // ================================================================

  var iconBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/icons/";


  var groupIcons = {

    "一键代理": "Proxy.png",

    "国内直连": "China.png",

    "AI": "AI.png",

    "YouTube": "YouTube.png",

    "Google": "Google.png",

    "GitHub": "GitHub.png",

    "网络检测": "Network-test.png",

    "Netflix": "Netflix.png",

    "Spotify": "Spotify.png",

    "Steam": "Steam.png",

    "Telegram": "Telegram.png",

    "TikTok": "TikTok.png",

    "Apple": "Apple.png",

    "Microsoft": "Microsoft.png",

    "ChatGPT": "AI.png",

    "Instagram": "Other.png",

    "香港": "Hong_Kong.png",

    "台湾": "Taiwan.png",

    "日本": "Japan.png",

    "新加坡": "Singapore.png",

    "韩国": "Korea.png",

    "美国": "United_States.png",

    "加拿大": "Other.png",

    "英国": "Other.png",

    "其他地区": "Other.png"

  };


  function getGroupIcon(name) {

    if (!groupIcons[name]) {

      return undefined;

    }

    return iconBaseURL + groupIcons[name];

  }


  // ================================================================
  // 10. Managed groups
  // ================================================================

  var managedGroups = {

    "一键代理": true,

    "国内直连": true,

    "AI": true,

    "ChatGPT": true,

    "Instagram": true,

    "YouTube": true,

    "Google": true,

    "GitHub": true,

    "网络检测": true,

    "Netflix": true,

    "Spotify": true,

    "Steam": true,

    "Telegram": true,

    "TikTok": true,

    "Apple": true,

    "Microsoft": true,

    "VPS节点": true,

    "优选节点": true,

    "MM节点": true,

    "6B节点": true,

    "AI节点": true,

    "美国节点": true,

    "香港": true,

    "台湾": true,

    "日本": true,

    "新加坡": true,

    "韩国": true,

    "美国": true,

    "加拿大": true,

    "英国": true,

    "其他地区": true

  };


  // ================================================================
  // 11. Built-in targets
  // ================================================================

  var builtinTargets = {

    "DIRECT": true,

    "REJECT": true,

    "REJECT-DROP": true,

    "PASS": true,

    "COMPATIBLE": true,

    "GLOBAL": true

  };


  // ================================================================
  // 12. Business group detection
  // ================================================================

  function isBusinessGroupName(name) {

    if (!name) {

      return false;

    }

    var text = String(name);


    var patterns = [

      /\bai\b/i,

      /openai/i,

      /chatgpt/i,

      /claude/i,

      /gemini/i,

      /netflix/i,

      /disney/i,

      /disney\+/i,

      /youtube/i,

      /google/i,

      /github/i,

      /spotify/i,

      /steam/i,

      /tiktok/i,

      /telegram/i,

      /twitter/i,

      /x\.com/i,

      /facebook/i,

      /instagram/i,

      /流媒体/i,

      /媒体/i,

      /影音/i,

      /视频/i,

      /游戏/i,

      /游戏专用/i,

      /机场专用/i,

      /节点分流/i

    ];


    for (var i = 0; i < patterns.length; i++) {

      if (patterns[i].test(text)) {

        return true;

      }

    }


    return false;

  }


  // ================================================================
  // 13. Auto-select detection
  // ================================================================

  function isAutoSelectGroup(name) {

    if (!name) {

      return false;

    }


    return (

      /自动选择/i.test(name) ||

      /auto[\s_-]*select/i.test(name) ||

      /auto[\s_-]*test/i.test(name) ||

      /测速/i.test(name)

    );

  }


  // ================================================================
  // 14. Failover detection
  // ================================================================

  function isFailoverGroup(name) {

    if (!name) {

      return false;

    }


    return (

      /故障转移/i.test(name) ||

      /failover/i.test(name) ||

      /fallback/i.test(name)

    );

  }


  // ================================================================
  // 15. All-node detection
  // ================================================================

  function isAllNodeName(name) {

    if (!name) {

      return false;

    }


    return (

      /全部节点/i.test(name) ||

      /所有节点/i.test(name) ||

      /全部/i.test(name) ||

      /all[\s_-]*nodes?/i.test(name) ||

      /all[\s_-]*proxies?/i.test(name)

    );

  }


  function getProxyComposition(group) {

    var result = {

      total: 0,

      actualNodes: 0,

      groups: 0,

      builtin: 0,

      unknown: 0

    };


    if (

      !group ||

      !Array.isArray(group.proxies)

    ) {

      return result;

    }


    result.total =
      group.proxies.length;


    group.proxies.forEach(function(item) {

      if (!item) {

        return;

      }


      if (proxyNames.indexOf(item) !== -1) {

        result.actualNodes++;

        return;

      }


      if (builtinTargets[item]) {

        result.builtin++;

        return;

      }


      var referencedGroup =
        originalGroups.some(function(g) {

          return (

            g &&

            g.name === item

          );

        });


      if (referencedGroup) {

        result.groups++;

        return;

      }


      result.unknown++;

    });


    return result;

  }


  function isAllNodesGroup(group) {

    if (!group || !group.name) {

      return false;

    }


    var name =
      String(group.name);


    if (isAllNodeName(name)) {

      return true;

    }


    if (isBusinessGroupName(name)) {

      return false;

    }


    var composition =
      getProxyComposition(group);


    if (composition.total === 0) {

      return false;

    }


    if (composition.actualNodes < 2) {

      return false;

    }


    var ratio =
      composition.actualNodes /
      composition.total;


    if (ratio < 0.3) {

      return false;

    }


    if (composition.groups > 0) {

      if (composition.actualNodes >= 5) {

        return true;

      }

      return false;

    }


    return true;

  }


  // ================================================================
  // 16. Preserve airport basic groups
  //
  // IMPORTANT:
  //
  // v1.5.1 fixed the problem where "九云" disappeared.
  //
  // Never force hidden=true.
  // ================================================================

  var preservedGroups = [];


  originalGroups.forEach(function(group) {

    if (!group || !group.name) {

      return;

    }


    if (managedGroups[group.name]) {

      return;

    }


    var isBasic =

      isAutoSelectGroup(group.name) ||

      isFailoverGroup(group.name) ||

      isAllNodesGroup(group);


    if (!isBasic) {

      return;

    }


    var copied =
      JSON.parse(JSON.stringify(group));


    // Keep airport group visible.

    delete copied["hidden"];


    preservedGroups.push(copied);

  });


  // ================================================================
  // 17. Convert airport Auto-Select groups to URL-Test
  // ================================================================

  preservedGroups.forEach(function(group) {

    if (!group || !group.name) {

      return;

    }


    if (!isAutoSelectGroup(group.name)) {

      return;

    }


    group.type = "url-test";


    group.proxies =
      proxyNames.slice();


    group.url =
      "https://www.gstatic.com/generate_204";


    group.interval = 300;


    group.timeout = 5000;


    group.tolerance = 50;


    group.lazy = true;


    group["max-failed-times"] = 3;


    group["expected-status"] = 204;


    delete group["disable-udp"];

    delete group["strategy"];

  });


  // ================================================================
  // 18. Find airport default manual selector
  //
  // Purpose:
  //
  //   Network Test
  //       ↓
  //   Airport Default Selector
  //       ↓
  //   User-selected node
  //
  // Example:
  //
  //   网络检测
  //       ↓
  //      九云
  //       ↓
  //      台湾节点
  //
  // Do NOT hardcode "九云".
  // ================================================================

  function findDefaultAirportGroup() {

    var candidates = [];


    originalGroups.forEach(function(group) {

      if (!group || !group.name) {

        return;

      }


      var name =
        String(group.name);


      // Ignore groups managed by Perfect-Rules.

      if (managedGroups[name]) {

        return;

      }


      // Ignore automatic groups.

      if (isAutoSelectGroup(name)) {

        return;

      }


      // Ignore failover groups.

      if (isFailoverGroup(name)) {

        return;

      }


      // Ignore obvious business groups.

      if (isBusinessGroupName(name)) {

        return;

      }


      if (group.type !== "select") {

        return;

      }


      var composition =
        getProxyComposition(group);


      if (composition.actualNodes < 2) {

        return;

      }


      candidates.push({

        group: group,

        score: 0,

        index: candidates.length

      });

    });


    // --------------------------------------------------------------
    // Prefer an all-node manual selector.
    //
    // This matches common airport structures such as:
    //
    //   九云
    //   节点
    //   全部节点
    //
    // where the group directly contains many actual proxy nodes.
    // --------------------------------------------------------------

    for (var i = 0; i < candidates.length; i++) {

      if (isAllNodesGroup(candidates[i].group)) {

        return candidates[i].group.name;

      }

    }


    // --------------------------------------------------------------
    // Fallback:
    //
    // Use the first suitable manual select group.
    // --------------------------------------------------------------

    if (candidates.length > 0) {

      return candidates[0].group.name;

    }


    return null;

  }


  var defaultAirportGroup =
    findDefaultAirportGroup();


  // ================================================================
  // 19. Remote Rule Provider base URL
  // ================================================================

  var ruleBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/rules/";


  // ================================================================
  // 20. Rule Provider factory
  // ================================================================

  function createRuleProvider(filename) {

    return {

      "type": "http",

      "behavior": "classical",

      "format": "yaml",

      "url": ruleBaseURL + filename,

      "path": "./rules/" + filename,

      "interval": 86400

    };

  }


  // ================================================================
  // 21. Remote Rule Providers
  //
  // GitHub repository:
  //
  // n0de-sudo/Perfect-Rules
  //
  // ================================================================

  config["rule-providers"] = {

    "AI":
      createRuleProvider("ai.yaml"),

    "YouTube":
      createRuleProvider("youtube.yaml"),

    "Google":
      createRuleProvider("google.yaml"),

    "GitHub":
      createRuleProvider("github.yaml"),

    "Netflix":
      createRuleProvider("netflix.yaml"),

    "Spotify":
      createRuleProvider("spotify.yaml"),

    "Steam":
      createRuleProvider("steam.yaml"),

    "Telegram":
      createRuleProvider("telegram.yaml"),

    "TikTok":
      createRuleProvider("tiktok.yaml"),

    "Apple":
      createRuleProvider("apple.yaml"),

    "Microsoft":
      createRuleProvider("microsoft.yaml"),

    "NetworkTest":
      createRuleProvider("network-test.yaml")

  };


  // ================================================================
  // 22. Region detection
  // ================================================================

  var regionPatterns = {

    "香港": [

      /港/i,
      /🇭🇰/,
      /香港/i,

      /\bHK\b/i,

      /HKG/i,

      /Hong\s*Kong/i,

      /HongKong/i

    ],


    "台湾": [

      /台/i,
      /🇹🇼/,
      /台湾/i,

      /台灣/i,

      /\bTW\b/i,

      /TPE/i,

      /KHH/i,

      /TSA/i,

      /Taiwan/i,

      /Taipei/i

    ],


    "日本": [

      /日/i,
      /🇯🇵/,
      /日本/i,

      /\bJP\b/i,

      /NRT/i,

      /HND/i,

      /KIX/i,

      /CTS/i,

      /FUK/i,

      /Japan/i,

      /Tokyo/i,

      /Osaka/i

    ],


    "新加坡": [

      /坡/i,
      /🇸🇬/,
      /新加坡/i,

      /\bSG\b/i,

      /SIN/i,

      /XSP/i,

      /Singapore/i

    ],


    "韩国": [

      /韩|韓/,
      /🇰🇷/,
      /韩国/i,

      /韓國/i,

      /\bKR\b/i,

      /ICN/i,

      /GMP/i,

      /PUS/i,

      /Korea/i,

      /Seoul/i

    ],


    "美国": [

      /美/i,
      /🇺🇸/,
      /美国/i,

      /\bUS\b/i,

      /\bUSA\b/i,

      /LAX/i,

      /SFO/i,

      /JFK/i,

      /SJC/i,

      /ORD/i,

      /ATL/i,

      /DFW/i,

      /MIA/i,

      /SEA/i,

      /IAD/i,

      /United\s*States/i,

      /America/i,

      /Los\s*Angeles/i,

      /San\s*Jose/i,

      /New\s*York/i

    ],


    "加拿大": [

      /加/i,
      /🇨🇦/,
      /加拿大/i,

      /Canada/i,

      /Toronto/i,

      /Vancouver/i,

      /Montreal/i

    ],


    "英国": [

      /英/i,
      /🇬🇧/,
      /英国/i,

      /\bUK\b/i,

      /United\s*Kingdom/i,

      /England/i,

      /London/i,

      /Manchester/i

    ]

  };


  function detectRegion(proxyName) {

    for (var region in regionPatterns) {

      if (!regionPatterns.hasOwnProperty(region)) {

        continue;

      }


      var patterns =
        regionPatterns[region];


      for (var i = 0; i < patterns.length; i++) {

        if (patterns[i].test(proxyName)) {

          return region;

        }

      }

    }


    return "其他地区";

  }


  // ================================================================
  // 23. Build region node lists
  // ================================================================

  var regionNodes = {

    "香港": [],

    "台湾": [],

    "日本": [],

    "新加坡": [],

    "韩国": [],

    "美国": [],

    "加拿大": [],

    "英国": [],

    "其他地区": []

  };

  var regionAirportNodes = {};
  var regionOtherNodes = {};
  var regionFreeNodes = {};

  function addRegionNode(bucket, region, proxyName) {

    if (!bucket[region]) {

      bucket[region] = [];

    }

    bucket[region].push(proxyName);

  }

  var airportNodePattern = /MM|霉霉|6B|牛逼/i;
  var freeNodePattern = /EdgeTunnel|FreeSocks|免费|free/i;


  originalProxies.forEach(function(proxy) {

    if (!proxy || !proxy.name) {

      return;

    }


    var region =
      detectRegion(String(proxy.name));


    regionNodes[region].push(

      proxy.name

    );

    var name = String(proxy.name);

    if (freeNodePattern.test(name)) {

      addRegionNode(regionFreeNodes, region, proxy.name);

    } else if (airportNodePattern.test(name)) {

      addRegionNode(regionAirportNodes, region, proxy.name);

    } else {

      addRegionNode(regionOtherNodes, region, proxy.name);

    }

  });


  // ================================================================
  // 24. Region order
  // ================================================================

  var regionOrder = [

    "香港",

    "台湾",

    "日本",

    "新加坡",

    "韩国",

    "美国",

    "加拿大",

    "英国",

    "其他地区"

  ];


  // ================================================================
  // 25. Create region URL-Test groups
  // ================================================================

  var regionGroups = [];
  var regionTierGroups = [];

  function createRegionTierGroup(name, nodes) {

    return {

      "name": name,

      "type": "url-test",

      "proxies": nodes,

      "url": "https://cp.cloudflare.com/generate_204",

      "interval": 120,

      "tolerance": 20

    };

  }

  function getUniqueRegionTierName(baseName) {

    var name = baseName;
    var suffix = 2;

    while (

      originalGroups.some(function(group) {

        return group && group.name === name;

      }) ||

      regionTierGroups.some(function(group) {

        return group.name === name;

      })

    ) {

      name = baseName + "-" + suffix;
      suffix++;

    }

    return name;

  }


  regionOrder.forEach(function(region) {

    var nodes =
      regionNodes[region];


    if (

      !nodes ||

      nodes.length === 0

    ) {

      return;

    }


    var tiers = [

      { suffix: "机场", nodes: regionAirportNodes[region] || [] },

      { suffix: "其他", nodes: regionOtherNodes[region] || [] },

      { suffix: "免费", nodes: regionFreeNodes[region] || [] }

    ].filter(function(tier) {

      return tier.nodes.length > 0;

    });

    var group;

    if (tiers.length > 1) {

      tiers.forEach(function(tier) {

        tier.groupName = getUniqueRegionTierName(region + tier.suffix);

        var tierGroup = createRegionTierGroup(

          tier.groupName,

          tier.nodes

        );

        var tierIcon = getGroupIcon(region);

        if (tierIcon) {

          tierGroup["icon"] = tierIcon;

        }

        regionTierGroups.push(

          tierGroup

        );

      });

      group = {

        "name": region,

        "type": "fallback",

        "proxies": tiers.map(function(tier) {

          return tier.groupName;

        }),

        "url": "https://cp.cloudflare.com/generate_204",

        "interval": 120

      };

    } else {

      group = {

        "name": region,

        "type": "url-test",

        "proxies": nodes,

        "url": "https://cp.cloudflare.com/generate_204",

        "interval": 120,

        "timeout": 5000,

        "tolerance": 20,

        "lazy": true,

        "max-failed-times": 3,

        "expected-status": 204

      };

    }


    var icon =
      getGroupIcon(region);


    if (icon) {

      group["icon"] = icon;

    }


    regionGroups.push(group);

  });


  var availableRegions =
    regionGroups.map(function(group) {

      return group.name;

    });


  // ================================================================
  // 26. Filtered node groups from the reference YAML
  // ================================================================

  var auxiliaryGroupDefinitions = [

    {
      name: "VPS节点",
      pattern: /VPS/i,
      icon: "plane-finder.svg"
    },

    {
      name: "优选节点",
      matches: function(name) {
        var region = detectRegion(name);
        return ["香港", "台湾", "日本", "新加坡"].indexOf(region) !== -1;
      },
      icon: "cloudflare-pages.svg"
    },

    {
      name: "MM节点",
      pattern: /MM/i,
      icon: "hermes-icon.svg"
    },

    {
      name: "6B节点",
      pattern: /6B/i,
      icon: "beef.svg"
    }

  ];

  var auxiliaryGroups = [];
  var auxiliaryIconBaseURL =
    "https://raw.githubusercontent.com/PlanetEditorX/Resource/refs/heads/main/icon/";

  auxiliaryGroupDefinitions.forEach(function(definition) {

    var nodes = proxyNames.filter(function(name) {

      return definition.matches
        ? definition.matches(String(name))
        : definition.pattern.test(String(name));

    });

    // Avoid emitting empty groups that some clients cannot select.
    if (nodes.length === 0) {

      return;

    }

    auxiliaryGroups.push({

      "name": definition.name,

      "type": "url-test",

      "proxies": nodes,

      "url": "https://cp.cloudflare.com/generate_204",

      "interval": 120,

      "timeout": 5000,

      "tolerance": 20,

      "lazy": true,

      "icon": auxiliaryIconBaseURL + definition.icon

    });

  });

  var usNodeGroup = null;

  if (availableRegions.indexOf("美国") !== -1) {

    usNodeGroup = {

      "name": "美国节点",

      "type": "select",

      "proxies": ["美国"],

      "default-selected": "美国",

      "icon": getGroupIcon("美国")

    };

  }

  var aiUSOnlyGroup = {

    "name": "AI",

    "type": "select",

    "proxies": usNodeGroup ? ["美国节点"] : ["REJECT"],

    "default-selected": usNodeGroup ? "美国节点" : "REJECT",

    "icon": getGroupIcon("AI")

  };

  var restrictedNodeOptions = [];

  if (auxiliaryGroups.some(function(group) {
    return group.name === "VPS节点";
  })) {

    restrictedNodeOptions.push("VPS节点");

  }

  if (usNodeGroup) {

    restrictedNodeOptions.push("美国节点");

  }

  if (restrictedNodeOptions.length === 0) {

    restrictedNodeOptions.push("REJECT");

  }

  var restrictedDefault =
    restrictedNodeOptions.indexOf("VPS节点") !== -1
      ? "VPS节点"
      : restrictedNodeOptions[0];

  function createRestrictedNodeGroup(name, icon) {

    return {

      "name": name,

      "type": "select",

      "proxies": restrictedNodeOptions.slice(),

      "default-selected": restrictedDefault,

      "icon": icon

    };

  }

  var restrictedNodeGroups = [

    createRestrictedNodeGroup(
      "ChatGPT",
      auxiliaryIconBaseURL + "chatgpt-big.svg"
    ),

    createRestrictedNodeGroup(
      "AI节点",
      auxiliaryIconBaseURL + "ai.svg"
    ),

    createRestrictedNodeGroup(
      "TikTok",
      auxiliaryIconBaseURL + "tiktok.svg"
    ),

    createRestrictedNodeGroup(
      "Instagram",
      auxiliaryIconBaseURL + "instagram.svg"
    )

  ];

  // ================================================================
  // 26. Domestic Direct
  // ================================================================

  var domesticDirectGroup = {

    "name": "国内直连",

    "type": "select",

    "proxies": [

      "DIRECT"

    ]

  };


  var domesticIcon =
    getGroupIcon("国内直连");


  if (domesticIcon) {

    domesticDirectGroup["icon"] =
      domesticIcon;

  }


  // ================================================================
  // 27. One-click Proxy
  // ================================================================

  var mainSelector = {

    "name": "一键代理",

    "type": "select",

    "proxies":
      availableRegions.concat([

        "国内直连"

      ])

  };


  var mainIcon =
    getGroupIcon("一键代理");


  if (mainIcon) {

    mainSelector["icon"] =
      mainIcon;

  }


  // ================================================================
  // 28. Service groups
  // ================================================================

  var businessRegionPreferences = {

    "YouTube": ["新加坡", "香港", "美国", "日本", "台湾"],

    "Google": ["香港", "美国", "新加坡", "日本", "台湾"],

    "GitHub": ["香港", "美国", "日本", "新加坡", "台湾"],

    "Netflix": ["新加坡", "美国", "日本", "香港", "台湾"],

    "Spotify": ["新加坡", "美国", "日本", "香港", "台湾"],

    "Steam": ["香港", "日本", "新加坡", "美国", "台湾"],

    "Telegram": ["香港", "新加坡", "日本", "美国", "台湾"],

    "Apple": ["香港", "美国", "新加坡", "日本", "台湾"],

    "Microsoft": ["香港", "美国", "新加坡", "日本", "台湾"]

  };

  function createBusinessGroup(name) {

    var preferredRegions = businessRegionPreferences[name] || availableRegions;
    var proxies = preferredRegions.filter(function(region) {

      return availableRegions.indexOf(region) !== -1;

    });

    availableRegions.forEach(function(region) {

      if (proxies.indexOf(region) === -1) {

        proxies.push(region);

      }

    });

    proxies.push("国内直连");

    var group = {

      "name": name,

      "type": "select",

      "proxies": proxies

    };


    var icon =
      getGroupIcon(name);


    if (icon) {

      group["icon"] = icon;

    }


    return group;

  }


  var businessGroups = [

    createBusinessGroup("YouTube"),

    createBusinessGroup("Google"),

    createBusinessGroup("GitHub"),

    createBusinessGroup("Netflix"),

    createBusinessGroup("Spotify"),

    createBusinessGroup("Steam"),

    createBusinessGroup("Telegram"),

    createBusinessGroup("Apple"),

    createBusinessGroup("Microsoft")

  ];


  // ================================================================
  // 29. Network Test
  //
  // IMPORTANT:
  //
  // Network Test follows the airport's default manual selector.
  //
  // Example:
  //
  //   九云
  //      ↓
  //   台湾节点
  //
  // Network Test:
  //
  //   网络检测
  //      ↓
  //     九云
  //      ↓
  //   台湾节点
  //
  // Therefore the network diagnostic websites will test the same
  // outbound proxy selected by the user in the airport's default
  // manual selector.
  //
  // ================================================================

  var networkTestGroup = {

    "name": "网络检测",

    "type": "select",

    "proxies": []

  };


  if (defaultAirportGroup) {

    networkTestGroup["proxies"] = [

      defaultAirportGroup

    ];

  } else {

    // Fallback:
    //
    // If no suitable airport manual selector can be detected,
    // follow the Perfect-Rules main selector instead.

    networkTestGroup["proxies"] = [

      "一键代理"

    ];

  }


  var networkTestIcon =
    getGroupIcon("网络检测");


  if (networkTestIcon) {

    networkTestGroup["icon"] =
      networkTestIcon;

  }


  // ================================================================
  // 30. Final proxy-group list
  //
  // IMPORTANT:
  //
  // Airport groups are preserved.
  //
  // Example:
  //
  //   九云
  //
  // remains visible.
  //
  // Network Test follows the airport default selector.
  //
  // ================================================================

  config["proxy-groups"] =

    preservedGroups

      .concat(businessGroups)

      .concat([

        networkTestGroup

      ])

      .concat(auxiliaryGroups)

      .concat(usNodeGroup ? [usNodeGroup] : [])

      .concat([aiUSOnlyGroup])

      .concat(restrictedNodeGroups)

      .concat(regionTierGroups)

      .concat(regionGroups)

      .concat([

        domesticDirectGroup,

        mainSelector

      ]);


  // ================================================================
  // 31. Routing rules
  //
  // IMPORTANT:
  //
  // Rule Providers are deliberately ordered:
  //
  // NetworkTest
  // AI
  // YouTube
  // Google
  // GitHub
  // Netflix
  // Spotify
  // Steam
  // Telegram
  // TikTok
  // Apple
  // Microsoft
  // CN / Private
  // MATCH
  //
  // YouTube MUST be before Google.
  //
  // ================================================================

  config["rules"] = [

    // Prevent clients from bypassing configured DNS over TLS / QUIC.
    "DST-PORT,853,REJECT",

    "DST-PORT,784,REJECT",

    // --------------------------------------------------------------
    // Private / LAN
    // --------------------------------------------------------------

    "DOMAIN-SUFFIX,lan,DIRECT",

    "DOMAIN-SUFFIX,local,DIRECT",

    "DOMAIN-SUFFIX,localhost,DIRECT",

    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",

    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",


    // --------------------------------------------------------------
    // Network Test
    // --------------------------------------------------------------

    "RULE-SET,NetworkTest,网络检测",


    // --------------------------------------------------------------
    // AI
    // --------------------------------------------------------------

    // ChatGPT / OpenAI are separated from the remaining AI services.
    "DOMAIN-SUFFIX,openai.com,ChatGPT",

    "DOMAIN-SUFFIX,chatgpt.com,ChatGPT",

    "DOMAIN-SUFFIX,oaistatic.com,ChatGPT",

    "DOMAIN-SUFFIX,oaiusercontent.com,ChatGPT",

    // Instagram service and media delivery domains.
    "DOMAIN-SUFFIX,instagram.com,Instagram",

    "DOMAIN-SUFFIX,cdninstagram.com,Instagram",

    "DOMAIN-SUFFIX,instagram.net,Instagram",

    "DOMAIN-SUFFIX,opencode.ai,AI",

    "DOMAIN-SUFFIX,models.dev,AI",

    "DOMAIN-SUFFIX,perplexity.ai,AI",

    "DOMAIN-SUFFIX,pplx.ai,AI",

    "DOMAIN-SUFFIX,grok.com,AI",

    "DOMAIN-SUFFIX,x.ai,AI",

    "DOMAIN-SUFFIX,deepseek.com,AI",

    "DOMAIN-SUFFIX,mistral.ai,AI",

    "DOMAIN-SUFFIX,openrouter.ai,AI",

    "DOMAIN-SUFFIX,groq.com,AI",

    "DOMAIN-SUFFIX,together.ai,AI",

    "DOMAIN-SUFFIX,together.xyz,AI",

    "DOMAIN-SUFFIX,fireworks.ai,AI",

    "DOMAIN-SUFFIX,cohere.com,AI",

    "DOMAIN-SUFFIX,huggingface.co,AI",

    "DOMAIN-SUFFIX,hf.co,AI",

    "DOMAIN-SUFFIX,replicate.com,AI",

    "DOMAIN-SUFFIX,poe.com,AI",

    "DOMAIN-SUFFIX,character.ai,AI",

    "DOMAIN-SUFFIX,cursor.com,AI",

    "DOMAIN-SUFFIX,cursor.sh,AI",

    "DOMAIN-SUFFIX,windsurf.com,AI",

    "DOMAIN-SUFFIX,codeium.com,AI",

    "DOMAIN-SUFFIX,cline.bot,AI",

    "DOMAIN-SUFFIX,v0.dev,AI",

    "DOMAIN-SUFFIX,lovable.dev,AI",

    "DOMAIN-SUFFIX,bolt.new,AI",

    "DOMAIN-SUFFIX,elevenlabs.io,AI",

    "DOMAIN-SUFFIX,midjourney.com,AI",

    "DOMAIN-SUFFIX,suno.com,AI",

    "DOMAIN-SUFFIX,runwayml.com,AI",

    "DOMAIN-SUFFIX,krea.ai,AI",

    "DOMAIN-SUFFIX,stability.ai,AI",

    "DOMAIN-SUFFIX,chatglm.cn,AI",

    "DOMAIN-SUFFIX,bigmodel.cn,AI",

    "DOMAIN-SUFFIX,kimi.com,AI",

    "DOMAIN-SUFFIX,moonshot.cn,AI",

    "DOMAIN-SUFFIX,qwen.ai,AI",

    "DOMAIN-SUFFIX,minimaxi.com,AI",

    "RULE-SET,AI,AI",


    // --------------------------------------------------------------
    // YouTube
    //
    // MUST be before Google.
    // --------------------------------------------------------------

    "RULE-SET,YouTube,YouTube",


    // --------------------------------------------------------------
    // Google
    // --------------------------------------------------------------

    "RULE-SET,Google,Google",


    // --------------------------------------------------------------
    // GitHub
    // --------------------------------------------------------------

    "RULE-SET,GitHub,GitHub",


    // --------------------------------------------------------------
    // Netflix
    // --------------------------------------------------------------

    "RULE-SET,Netflix,Netflix",


    // --------------------------------------------------------------
    // Spotify
    // --------------------------------------------------------------

    "RULE-SET,Spotify,Spotify",


    // --------------------------------------------------------------
    // Steam
    // --------------------------------------------------------------

    "RULE-SET,Steam,Steam",


    // --------------------------------------------------------------
    // Telegram
    // --------------------------------------------------------------

    "RULE-SET,Telegram,Telegram",


    // --------------------------------------------------------------
    // TikTok
    // --------------------------------------------------------------

    "RULE-SET,TikTok,TikTok",


    // --------------------------------------------------------------
    // Apple
    // --------------------------------------------------------------

    "RULE-SET,Apple,Apple",


    // --------------------------------------------------------------
    // Microsoft
    // --------------------------------------------------------------

    "RULE-SET,Microsoft,Microsoft",


    // --------------------------------------------------------------
    // Private
    // --------------------------------------------------------------

    "GEOSITE,private,国内直连",

    "GEOIP,private,国内直连,no-resolve",


    // --------------------------------------------------------------
    // China
    // --------------------------------------------------------------

    "GEOSITE,cn,国内直连",

    "GEOIP,cn,国内直连,no-resolve",


    // --------------------------------------------------------------
    // Final
    // --------------------------------------------------------------

    "MATCH,一键代理"

  ];


  // ================================================================
  // 32. Return generated config
  // ================================================================

  return config;

}
