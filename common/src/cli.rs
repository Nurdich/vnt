use crate::args_parse::{ips_parse, out_ips_parse};
#[cfg(feature = "command")]
use crate::command;
use crate::{config, generated_serial_number};
use anyhow::anyhow;
use console::style;
use getopts::Options;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use sys_locale::get_locale;
use vnt::channel::punch::PunchModel;
use vnt::channel::UseChannelType;
use vnt::cipher::CipherModel;
use vnt::compression::Compressor;
use vnt::core::Config;

pub fn app_home() -> io::Result<PathBuf> {
    let root_path = match std::env::current_exe() {
        Ok(path) => {
            if let Some(v) = path.as_path().parent() {
                v.to_path_buf()
            } else {
                log::warn!("current_exe parent none:{:?}", path);
                PathBuf::new()
            }
        }
        Err(e) => {
            log::warn!("current_exe err:{:?}", e);
            PathBuf::new()
        }
    };
    let path = root_path.join("env");
    if !path.exists() {
        std::fs::create_dir_all(&path)?;
    }
    Ok(path)
}

fn get_default_config() -> Config {
    Config::new(
        #[cfg(feature = "integrated_tun")]
        #[cfg(target_os = "windows")]
        false, // 默认不使用 tap 模式
        "liangcang".to_string(), // 默认 token
        config::get_device_id(), // 使用默认的设备 ID
        gethostname::gethostname().to_str().unwrap_or("UnknownName").to_string(), // 默认设备名称
        "udp://vpn.chd.one:8443".to_string(), // 默认服务器地址
        Vec::new(), // 默认 DNS 为空
        config::PUB_STUN.iter().map(|&s| s.to_string()).collect(), // 默认 STUN 服务器
        Vec::new(), // 默认入站 IP 为空
        vec!["0.0.0.0/0".parse().unwrap()], // 默认出站 IP 为所有 IP
        Some("liangcang".to_string()), // 默认密码
        None, // 默认 MTU
        None, // 默认虚拟 IP
        #[cfg(feature = "integrated_tun")]
        #[cfg(feature = "ip_proxy")]
        false, // 默认不禁用代理
        false, // 默认不使用服务器加密
        CipherModel::AesGcm, // 默认加密模式
        false, // 默认不使用指纹校验
        PunchModel::All, // 默认打洞模式
        None, // 默认端口
        false, // 默认不优先低延迟
        #[cfg(feature = "integrated_tun")]
        None, // 默认设备名称
        UseChannelType::All, // 默认使用所有通道类型
        None, // 默认不模拟丢包
        0, // 默认不模拟延迟
        #[cfg(feature = "port_mapping")]
        Vec::new(), // 默认端口映射为空
        Compressor::Lz4, // 默认使用 LZ4 压缩
        true, // 默认启用流量统计
        false, // 默认不允许 WireGuard
        None, // 默认本地 IPv4
    ).expect("Default configuration should be valid")
}

pub fn parse_args_config() -> anyhow::Result<Option<(Config, Vec<String>, bool)>> {
    #[cfg(feature = "log")]
    let _ = log4rs::init_file("log4rs.yaml", Default::default());
    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("k", "", "组网标识", "<token>");
    opts.optopt("n", "", "设备名称", "<name>");
    opts.optopt("d", "", "设备标识", "<id>");
    opts.optflag("c", "", "关闭交互式命令");
    opts.optopt("s", "", "注册和中继服务器地址", "<server>");
    opts.optmulti("e", "", "stun服务器", "<stun-server>");
    opts.optflag("a", "", "使用tap模式");
    opts.optopt("", "nic", "虚拟网卡名称,windows下使用tap则必填", "<tun0>");
    opts.optmulti("i", "", "配置点对网(IP代理)入站时使用", "<in-ip>");
    opts.optmulti("o", "", "配置点对网出站时使用", "<out-ip>");
    opts.optopt("w", "", "客户端加密", "<password>");
    opts.optflag("W", "", "服务端加密");
    opts.optopt("u", "", "自定义mtu(默认为1430)", "<mtu>");
    opts.optopt("", "ip", "指定虚拟ip", "<ip>");
    opts.optflag("", "relay", "仅使用服务器转发");
    opts.optopt("", "par", "任务并行度(必须为正整数)", "<parallel>");
    opts.optopt("", "model", "加密模式", "<model>");
    opts.optflag("", "finger", "指纹校验");
    opts.optopt("", "punch", "取值ipv4/ipv6", "<punch>");
    opts.optopt("", "ports", "监听的端口", "<port,port>");
    opts.optflag("", "cmd", "开启窗口输入");
    opts.optflag("", "no-proxy", "关闭内置代理");
    opts.optflag("", "first-latency", "优先延迟");
    opts.optopt("", "use-channel", "使用通道 relay/p2p", "<use-channel>");
    opts.optopt("", "packet-loss", "丢包率", "<packet-loss>");
    opts.optopt("", "packet-delay", "延迟", "<packet-delay>");
    opts.optmulti("", "dns", "dns", "<dns>");
    opts.optmulti("", "mapping", "mapping", "<mapping>");
    opts.optmulti("", "vnt-mapping", "vnt-mapping", "<mapping>");
    opts.optopt("f", "", "配置文件", "<conf>");
    opts.optopt("", "compressor", "压缩算法", "<lz4>");
    opts.optopt("", "local-ipv4", "指定本地ipv4网卡IP", "<IP>");
    opts.optflag("", "disable-stats", "关闭流量统计");
    opts.optflag("", "allow-wg", "允许接入WireGuard");
    //"后台运行时,查看其他设备列表"
    opts.optflag("", "add", "后台运行时,添加地址");
    opts.optflag("", "list", "后台运行时,查看其他设备列表");
    opts.optflag("", "all", "后台运行时,查看其他设备完整信息");
    opts.optflag("", "info", "后台运行时,查看当前设备信息");
    opts.optflag("", "route", "后台运行时,查看数据转发路径");
    opts.optflag("", "chart_a", "后台运行时,查看流量统计");
    opts.optopt("", "chart_b", "后台运行时,查看流量统计", "<IP>");
    opts.optflag("", "stop", "停止后台运行");
    opts.optflag("h", "help", "帮助");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            print_usage(&program, opts);
            return Err(anyhow::anyhow!("{}", f.to_string()));
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(None);
    }

    // 如果没有提供任何参数，使用默认配置
    if args.len() == 1 {
        let default_config = get_default_config();
        println!("使用默认配置运行程序。");
        println!("version {}", vnt::VNT_VERSION);
        println!("Serial:{}", generated_serial_number::SERIAL_NUMBER);
        log::info!(
            "version:{},Serial:{}",
            vnt::VNT_VERSION,
            generated_serial_number::SERIAL_NUMBER
        );
        return Ok(Some((default_config, Vec::new(), false)));
    }

    // ... (保留其余的代码，包括所有的 #[cfg(feature = "command")] 块)

    let conf = matches.opt_str("f");
    let (config, vnt_link_config, cmd) = if conf.is_some() {
        match config::read_config(&conf.unwrap()) {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow::anyhow!("conf err {}", e));
            }
        }
    } else {
        let default_config = get_default_config();
        
        let token = matches.opt_str("k").unwrap_or(default_config.token);
        let device_id = matches.opt_get_default("d", default_config.device_id).unwrap();
        let name = matches.opt_get_default("n", default_config.name).unwrap();
        let server_address_str = matches.opt_get_default("s", default_config.server_address).unwrap();

        let mut stun_server = matches.opt_strs("e");
        if stun_server.is_empty() {
            stun_server = default_config.stun_server;
        }

        let dns = matches.opt_strs("dns");
        let in_ip = match ips_parse(&matches.opt_strs("i")) {
            Ok(in_ip) => in_ip,
            Err(e) => {
                print_usage(&program, opts);
                println!();
                println!("-i: {:?} {}", matches.opt_strs("i"), e);
                return Err(anyhow::anyhow!("example: -i 192.168.0.0/24,10.26.0.3"));
            }
        };
        let out_ip = match out_ips_parse(&matches.opt_strs("o")) {
            Ok(out_ip) => out_ip,
            Err(e) => {
                print_usage(&program, opts);
                println!();
                println!("-o: {:?} {}", matches.opt_strs("o"), e);
                return Err(anyhow::anyhow!("example: -o 0.0.0.0/0"));
            }
        };
        let password = matches.opt_get("w").unwrap().or(default_config.password);
        let server_encrypt = matches.opt_present("W");
        let mtu = matches.opt_get("u").unwrap().or(default_config.mtu);
        let virtual_ip = matches.opt_get("ip").unwrap().or(default_config.virtual_ip);
        let relay = matches.opt_present("relay");

        let cipher_model = match matches.opt_get::<CipherModel>("model") {
            Ok(model) => model.unwrap_or(default_config.cipher_model),
            Err(e) => {
                return Err(anyhow::anyhow!("'--model ' invalid,{}", e));
            }
        };

        let finger = matches.opt_present("finger");
        let punch_model = matches.opt_get::<PunchModel>("punch").unwrap().unwrap_or(default_config.punch_model);
        let use_channel_type = matches.opt_get::<UseChannelType>("use-channel").unwrap().unwrap_or(default_config.use_channel_type);
        let ports = matches.opt_get::<String>("ports").unwrap_or(None).map(|v| v.split(",").map(|x| x.parse().unwrap_or(0)).collect());
        let cmd = matches.opt_present("cmd");
        #[cfg(feature = "ip_proxy")]
        #[cfg(feature = "integrated_tun")]
        let no_proxy = matches.opt_present("no-proxy");
        let first_latency = matches.opt_present("first-latency");
        let packet_loss = matches.opt_get::<f64>("packet-loss").unwrap_or(default_config.packet_loss);
        let packet_delay = matches.opt_get::<u32>("packet-delay").unwrap_or(Some(default_config.packet_delay)).unwrap();
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = matches.opt_strs("mapping");
        let vnt_mapping_list = matches.opt_strs("vnt-mapping");
        let local_ipv4 = matches.opt_get("local-ipv4").unwrap().or(default_config.local_ipv4);
        let disable_stats = matches.opt_present("disable-stats");
        let allow_wire_guard = matches.opt_present("allow-wg");
        let compressor = if let Some(compressor) = matches.opt_str("compressor").as_ref() {
            Compressor::from_str(compressor).map_err(|e| anyhow!("{}", e)).unwrap()
        } else {
            default_config.compressor
        };

        let config = Config::new(
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            matches.opt_present("a"),
            token,
            device_id,
            name,
            server_address_str,
            dns,
            stun_server,
            in_ip,
            out_ip,
            password,
            mtu,
            virtual_ip,
            #[cfg(feature = "integrated_tun")]
            #[cfg(feature = "ip_proxy")]
            no_proxy,
            server_encrypt,
            cipher_model,
            finger,
            punch_model,
            ports,
            first_latency,
            #[cfg(feature = "integrated_tun")]
            matches.opt_str("nic"),
            use_channel_type,
            packet_loss,
            packet_delay,
            #[cfg(feature = "port_mapping")]
            port_mapping_list,
            compressor,
            !disable_stats,
            allow_wire_guard,
            local_ipv4,
        )?;
        (config, vnt_mapping_list, cmd)
    };

    println!("version {}", vnt::VNT_VERSION);
    println!("Serial:{}", generated_serial_number::SERIAL_NUMBER);
    log::info!(
        "version:{},Serial:{}",
        vnt::VNT_VERSION,
        generated_serial_number::SERIAL_NUMBER
    );
    Ok(Some((config, vnt_link_config, cmd)))
}

fn get_description(key: &str, language: &str) -> String {
    // 设置一个全局的映射来存储中英文对照
    let descriptions: HashMap<&str, (&str, &str)> = [
        ("-k <token>", ("使用相同的token,就能组建一个局域网络", "Use the same token to form a local network")),
        ("-n <name>", ("给设备一个名字,便于区分不同设备,默认使用系统版本", "Give the device a name to distinguish it, defaults to system version")),
        ("-d <id>", ("设备唯一标识符,不使用--ip参数时,服务端凭此参数分配虚拟ip,注意不能重复", "Device unique identifier, used by the server to allocate virtual IP when --ip parameter is not used, must be unique")),
        ("-s <server>", ("注册和中继服务器地址,协议支持使用tcp://和ws://和wss://,默认为udp://", "Registration and relay server address, protocols support using tcp://, ws://, and wss://, default is udp://")),
        ("-e <stun-server>", ("stun服务器,用于探测NAT类型,可使用多个地址,如-e stun.miwifi.com -e turn.cloudflare.com", "STUN server for detecting NAT type, can specify multiple addresses, e.g., -e stun.miwifi.com -e turn.cloudflare.com")),
        ("-a", ("使用tap模式,默认使用tun模式,使用tap时需要配合'--nic'参数指定tap网卡", "Use tap mode, default is tun mode, specify '--nic' parameter with tap network card")),
        ("-i <in-ip>", ("配置点对网(IP代理)时使用,-i 192.168.0.0/24,10.26.0.3表示允许接收网段192.168.0.0/24的数据并转发到10.26.0.3,可指定多个网段", "Used when configuring point-to-point network (IP proxy), -i 192.168.0.0/24,10.26.0.3 allows receiving data from subnet 192.168.0.0/24 and forwarding to 10.26.0.3, specify multiple subnets")),
        ("-o <out-ip>", ("配置点对网时使用,-o 192.168.0.0/24表示允许将数据转发到192.168.0.0/24,可指定多个网段", "Used when configuring point-to-point network, -o 192.168.0.0/24 allows forwarding data to 192.168.0.0/24, specify multiple subnets")),
        ("-w <password>", ("使用该密码生成的密钥对客户端数据进行加密,并且服务端无法解密,使用相同密码的客户端才能通信", "Encrypt client data with keys generated by this password, server cannot decrypt, clients must use the same password to communicate")),
        ("-W", ("加密当前客户端和服务端通信的数据,请留意服务端指纹是否正确", "Encrypt the data currently being communicated between the client and server, please pay attention to whether the server fingerprint is correct")),
        ("-u <mtu>", ("自定义mtu(默认为1420)", "Customize MTU (default is 1420)")),
        ("-f <conf_file>", ("读取配置文件中的配置", "Read configuration from file")),
        ("--ip <ip>", ("指定虚拟ip,指定的ip不能和其他设备重复,必须有效并且在服务端所属网段下,默认情况由服务端分配", "Specify virtual IP, must be unique and valid within server subnet, by default allocated by server")),
        ("--model <model>", ("加密模式(默认aes_gcm),可选值", "Encryption mode (default aes_gcm), options ")),
        ("--finger", ("增加数据指纹校验,可增加安全性,如果服务端开启指纹校验,则客户端也必须开启", "Add data fingerprint verification for increased security, client must enable if server does")),
        ("--punch <punch>", ("取值ipv4/ipv6/ipv4-tcp/ipv4-udp/ipv6-tcp/ipv6-udp/all,ipv4表示仅使用ipv4打洞", "Values ipv4/ipv6/ipv4-tcp/ipv4-udp/ipv6-tcp/ipv6-udp/all, ipv4 for IPv4 hole punching only")),
        ("--ports <port,port>", ("取值0~65535,指定本地监听的一组端口,默认监听两个随机端口,使用过多端口会增加网络负担", "Values 0~65535, specify a group of local listening ports, defaults to two random ports, using many ports increases network load")),
        ("--cmd", ("开启交互式命令,使用此参数开启控制台输入", "Enable interactive command mode, use this parameter to enable console input")),
        ("--no-proxy", ("关闭内置代理,如需点对网则需要配置网卡NAT转发", "Disable built-in proxy, configure network card NAT forwarding for point-to-point networking")),
        ("--first-latency", ("优先低延迟的通道,默认情况优先使用p2p通道", "Prioritize low-latency channels, defaults to prioritizing p2p channel")),
        ("--use-channel <p2p>", ("使用通道 relay/p2p/all,默认两者都使用", "Use channel relay/p2p/all, defaults to using both")),
        ("--nic <tun0>", ("指定虚拟网卡名称", "Specify virtual network card name")),
        ("--packet-loss <0>", ("模拟丢包,取值0~1之间的小数,程序会按设定的概率主动丢包,可用于模拟弱网", "Simulate packet loss, value between 0 and 1, program actively drops packets based on set probability, useful for simulating weak networks")),
        ("--packet-delay <0>", ("模拟延迟,正整数,单位毫秒,程序将根据设定值延迟发送数据包,可用于模拟弱网", "Simulate latency, integer, in milliseconds (ms). The program will delay sending packets according to the set value and can be used to simulate weak networks")),
        ("--dns <host:port>", ("DNS服务器地址,可使用多个dns,不指定时使用系统解析", "DNS server address, can specify multiple DNS servers, defaults to system resolution if not specified")),
        ("--mapping <mapping>", ("端口映射,例如 --mapping udp:0.0.0.0:80-domain:80 映射目标是本地路由能访问的设备", "Port mapping, e.g., --mapping udp:0.0.0.0:80-domain:80 maps to a device accessible by local routing")),
        ("--compressor-all <lz4>", ("启用压缩,可选值lz4/zstd<,level>,level为压缩级别,例如 --compressor lz4 或--compressor zstd,10", "Enable compression, options lz4/zstd<,level>, level is compression level, e.g., --compressor lz4 or --compressor zstd,10")),
        ("--compressor-lz4 <lz4>", ("启用压缩,可选值lz4,例如 --compressor lz4", "Enable compression, option lz4, e.g., --compressor lz4")),
        ("--compressor-zstd <zstd>", ("启用压缩,可选值zstd<,level>,level为压缩级别,例如 --compressor zstd,10", "Enable compression, options zstd<,level>, level is compression level, e.g., --compressor zstd,10")),
        ("--vnt-mapping <x>", ("vnt地址映射,例如 --vnt-mapping tcp:80-10.26.0.10:80 映射目标是vnt网络或其子网中的设备", "VNT address mapping, e.g., --vnt-mapping tcp:80-10.26.0.10:80 maps to a device in VNT network or its subnet")),
        ("--local-ipv4", ("本地出口网卡的ipv4地址", "IPv4 address of local export network card")),
        ("--disable-stats", ("关闭流量统计", "Disable traffic statistics")),
        ("--allow-wg", ("允许接入WireGuard客户端", "Allow access to WireGuard client")),
        ("--list", ("后台运行时,查看其他设备列表", "View list of other devices when running in background")),
        ("--all", ("后台运行时,查看其他设备完整信息", "View complete information of other devices when running in background")),
        ("--info", ("后台运行时,查看当前设备信息", "View information of current device when running in background")),
        ("--route", ("后台运行时,查看数据转发路径", "View data forwarding path when running in background")),
        ("--chart_a", ("后台运行时,查看所有IP的流量统计", "View traffic statistics of all IPs when running in background")),
        ("--chart_b <IP>", ("后台运行时,查看单个IP的历史流量", "View historical traffic of a single IP when running in background")),
        ("--stop", ("停止后台运行", "Stop running in background"))
        // ... 其他选项
    ]
    .iter()
    .cloned()
    .collect();

    if let Some(&(zh, en)) = descriptions.get(key) {
        if language.starts_with("zh") {
            return zh.to_string(); // 返回 String 类型
        }
        // 默认返回英文
        return en.to_string(); // 返回 String 类型
    }
    // 如果没有找到对应的键，则返回空字符串
    String::new()
}

fn print_usage(program: &str, _opts: Options) {
    // 获取系统语言  Locale::user_default().unwrap_or_else(|_| Locale::default());
    let language = get_locale().unwrap_or_else(|| String::from("en-US"));
    println!("Usage: {} [options]", program);
    println!("version:{}", vnt::VNT_VERSION);
    println!("Serial:{}", generated_serial_number::SERIAL_NUMBER);
    println!("Options:");
    println!(
        "  -k <token>          {}",
        green(get_description("-k <token>", &language).to_string())
    );
    println!(
        "  -n <name>           {}",
        get_description("-n <name>", &language)
    );
    println!(
        "  -d <id>             {}",
        get_description("-d <id>", &language)
    );
    println!(
        "  -s <server>         {}",
        get_description("-s <server>", &language)
    );
    println!(
        "  -e <stun-server>    {}",
        get_description("-e <stun-server>", &language)
    );
    #[cfg(target_os = "windows")]
    #[cfg(feature = "integrated_tun")]
    println!("  -a                  {}", get_description("-a", &language));
    println!(
        "  -i <in-ip>          {}",
        get_description("-i <in-ip>", &language)
    );
    println!(
        "  -o <out-ip>         {}",
        get_description("-o <out-ip>", &language)
    );
    println!(
        "  -w <password>       {}",
        get_description("-w <password>", &language)
    );
    #[cfg(feature = "server_encrypt")]
    println!("  -W                  {}", get_description("-W", &language));
    println!(
        "  -u <mtu>            {}",
        get_description("-u <mtu>", &language)
    );
    #[cfg(feature = "file_config")]
    println!(
        "  -f <conf_file>      {}",
        get_description("-f <conf_file>", &language)
    );

    println!(
        "  --ip <ip>           {}",
        get_description("--ip <ip>", &language)
    );
    let mut enums = String::new();
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    enums.push_str("/aes_gcm");
    #[cfg(feature = "chacha20_poly1305")]
    enums.push_str("/chacha20_poly1305/chacha20");
    #[cfg(feature = "aes_cbc")]
    enums.push_str("/aes_cbc");
    #[cfg(feature = "aes_ecb")]
    enums.push_str("/aes_ecb");
    #[cfg(feature = "sm4_cbc")]
    enums.push_str("/sm4_cbc");
    enums.push_str("/xor");
    println!(
        "  --model <model>     {}{}",
        get_description("--model <model>", &language),
        &enums[1..]
    );
    #[cfg(any(
        feature = "aes_gcm",
        feature = "chacha20_poly1305",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    ))]
    println!(
        "  --finger            {}",
        get_description("--finger", &language)
    );
    println!(
        "  --punch <punch>     {}",
        get_description("--punch <punch>", &language)
    );
    println!(
        "  --ports <port,port> {}",
        get_description("--ports <port,port>", &language)
    );
    #[cfg(feature = "command")]
    println!(
        "  --cmd               {}",
        get_description("--cmd", &language)
    );
    #[cfg(feature = "ip_proxy")]
    #[cfg(feature = "integrated_tun")]
    println!(
        "  --no-proxy          {}",
        get_description("--no-proxy", &language)
    );
    println!(
        "  --first-latency     {}",
        get_description("--first-latency", &language)
    );
    println!(
        "  --use-channel <p2p> {}",
        get_description("--use-channel <p2p>", &language)
    );
    #[cfg(not(feature = "vn-link-model"))]
    println!(
        "  --nic <tun0>        {}",
        get_description("--nic <tun0>", &language)
    );
    println!(
        "  --packet-loss <0>   {}",
        get_description("--packet-loss <0>", &language)
    );
    println!(
        "  --packet-delay <0>  {}",
        get_description("--packet-delay <0>", &language)
    );
    println!(
        "  --dns <host:port>   {}",
        get_description("--dns <host:port>", &language)
    );

    #[cfg(feature = "port_mapping")]
    println!(
        "  --mapping <mapping> {}",
        get_description("--mapping <mapping>", &language)
    );

    #[cfg(all(feature = "lz4", feature = "zstd"))]
    println!(
        "  --compressor <lz4>  {}",
        get_description("--compressor-all <lz4>", &language)
    );
    #[cfg(feature = "lz4")]
    #[cfg(not(feature = "zstd"))]
    println!(
        "  --compressor <lz4>  {}",
        get_description("--compressor-lz4 <lz4>", &language)
    );
    #[cfg(feature = "zstd")]
    #[cfg(not(feature = "lz4"))]
    println!(
        "  --compressor <zstd> {}",
        get_description("--compressor-zstd <zstd>", &language)
    );

    #[cfg(not(feature = "integrated_tun"))]
    println!(
        "  --vnt-mapping <x>   {}",
        green(get_description("--vnt-mapping <x>", &language).to_string())
    );
    println!(
        "  --local-ipv4 <IP>   {}",
        get_description("--local-ipv4", &language)
    );
    println!(
        "  --disable-stats     {}",
        get_description("--disable-stats", &language)
    );
    println!(
        "  --allow-wg          {}",
        get_description("--allow-wg", &language)
    );
    println!();
    #[cfg(feature = "command")]
    {
        // #[cfg(not(feature = "integrated_tun"))]
        // println!(
        //     "  --add               {}",
        //     yellow("后台运行时,添加VNT地址映射 用法同'--vnt-mapping'".to_string())
        // );
        println!(
            "  --list              {}",
            yellow(get_description("--list", &language).to_string())
        );
        println!(
            "  --all               {}",
            yellow(get_description("--all", &language).to_string())
        );
        println!(
            "  --info              {}",
            yellow(get_description("--info", &language).to_string())
        );
        println!(
            "  --route             {}",
            yellow(get_description("--route", &language).to_string())
        );
        println!(
            "  --chart_a           {}",
            yellow(get_description("--chart_a", &language).to_string())
        );
        println!(
            "  --chart_b <IP>      {}",
            yellow(get_description("--chart_b <IP>", &language).to_string())
        );
        println!(
            "  --stop              {}",
            yellow(get_description("--stop", &language).to_string())
        );
    }
    println!("  -h, --help          display help information(显示帮助信息)");
}

fn green(str: String) -> impl std::fmt::Display {
    style(str).green()
}

#[cfg(feature = "command")]
fn yellow(str: String) -> impl std::fmt::Display {
    style(str).yellow()
}
