import { connect } from 'cloudflare:sockets';

// 工具函数模块
const Utils = {
  // 安全的 UUID 验证
  isValidUUID(uuid) {
    const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return regex.test(uuid);
  },

  // 安全的 SHA-256 哈希
  async sha256Hash(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // 安全解析逗号分隔的字符串为数组
  parseList(input = '') {
    try {
      return input.split(',')
        .map(item => item.trim())
        .filter(item => item !== '');
    } catch {
      return [];
    }
  },

  // 安全路径过滤
  safePath(input) {
    return input.replace(/[^a-zA-Z0-9\-_=]/g, '');
  },

  // SOCKS5 地址解析
  socks5AddressParser(address) {
    const parts = address.split(':');
    if (parts.length < 2) throw new Error('Invalid SOCKS5 address');
    
    const port = parseInt(parts[1], 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      throw new Error('Invalid port number');
    }
    
    return {
      host: parts[0],
      port: port
    };
  },

  // 生成错误响应
  errorResponse(status, message) {
    return new Response(message, {
      status,
      headers: { 'Content-Type': 'text/plain;charset=utf-8' }
    });
  }
};

// 配置管理
class Config {
  constructor(env) {
    // 核心配置
    this.userID = env.UUID || '';
    this.proxyIP = env.PROXY_IP || '';
    this.dns64Server = env.DNS64 || 'dns64.cmliuss.net';
    
    // 订阅配置
    this.subConverter = env.SUB_API || 'subapi.cmliuss.net';
    this.subConfig = env.SUB_CONFIG || 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini';
    this.subEmoji = !['0', 'false'].includes(env.SUB_EMOJI?.toLowerCase());
    
    // SOCKS5 配置
    this.socks5Address = env.SOCKS5 || '';
    this.enableSocks = false;
    this.enableHttp = false;
    
    // 安全配置
    this.allowInsecure = !['0', 'false'].includes(env.ALLOW_INSECURE?.toLowerCase());
    this.banHosts = Utils.parseList(env.BAN) || ['speed.cloudflare.com'];
    
    // 动态 UUID 设置
    this.dynamic = {
      key: env.DYNAMIC_KEY || '',
      validDays: Number(env.VALID_DAYS) || 7,
      updateHours: Number(env.UPDATE_HOURS) || 3
    };
    
    // 初始化解析
    this.parseSocks5Address();
    this.validateUUID();
  }
  
  parseSocks5Address() {
    if (!this.socks5Address) return;
    
    try {
      const address = this.socks5Address.includes('//') 
        ? this.socks5Address.split('//')[1] 
        : this.socks5Address;
      
      this.parsedSocks5Address = Utils.socks5AddressParser(address);
      this.enableSocks = true;
      this.enableHttp = address.toLowerCase().includes('http://');
    } catch (error) {
      console.error(`SOCKS5解析错误: ${error.message}`);
      this.enableSocks = false;
    }
  }
  
  validateUUID() {
    if (!this.userID) {
      throw new Error('请设置UUID环境变量');
    }
    
    if (!Utils.isValidUUID(this.userID) && !this.dynamic.key) {
      throw new Error(`无效的UUID格式: ${this.userID}`);
    }
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      // 初始化配置
      const config = new Config(env);
      
      // 处理动态 UUID
      if (!Utils.isValidUUID(config.userID) && config.dynamic.key) {
        const timestamp = Math.floor(Date.now() / 1000);
        const input = `${config.dynamic.key}${timestamp}`;
        const hash = await Utils.sha256Hash(input);
        
        // 格式化为 UUID v4 (8-4-4-4-12)
        config.userID = [
          hash.substring(0, 8),
          hash.substring(8, 12),
          '4' + hash.substring(13, 15), // 版本4标识
          hash.substring(16, 20),
          hash.substring(20, 32)
        ].join('-');
      }
      
      // 检查 WebSocket 升级
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader === 'websocket') {
        return this.handleWebSocket(request, config);
      }
      
      // 处理 HTTP 请求
      return this.handleHttpRequest(request, config, env);
    } catch (error) {
      return Utils.errorResponse(500, `服务器错误: ${error.message}`);
    }
  },
  
  async handleWebSocket(request, config) {
    try {
      const webSocketPair = new WebSocketPair();
      const [client, server] = Object.values(webSocketPair);
      
      server.accept();
      const ws = connect({
        hostname: config.proxyIP || "proxy.example.com",
        port: 443
      });
      
      server.addEventListener('message', (msg) => {
        ws.write(msg.data);
      });
      
      ws.addEventListener('message', (msg) => {
        server.send(msg.data);
      });
      
      return new Response(null, {
        status: 101,
        webSocket: client
      });
    } catch (error) {
      return Utils.errorResponse(500, `WebSocket失败: ${error.message}`);
    }
  },
  
  async handleHttpRequest(request, config, env) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase();
    
    // 路由处理
    switch (path) {
      case '/':
        return this.handleRootRequest(request, config, env);
      case '/subscribe':
        return this.generateSubscription(url, config);
      case '/config':
        return this.fetchConfig(config);
      default:
        return Utils.errorResponse(404, '未找到页面');
    }
  },
  
  async handleRootRequest(request, config, env) {
    if (env.REDIRECT_URL) {
      return Response.redirect(env.REDIRECT_URL, 302);
    }
    
    const info = {
      status: 'active',
      uuid: config.userID,
      proxy_ip: config.proxyIP || 'auto',
      socks5: config.enableSocks ? `${config.parsedSocks5Address.host}:${config.parsedSocks5Address.port}` : 'disabled'
    };
    
    return new Response(JSON.stringify(info, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  },
  
  async generateSubscription(url, config) {
    const params = url.searchParams;
    const useTLS = params.get('tls') !== 'false';
    const customHost = params.get('host') || 'your.domain';
    const baseUrl = `${useTLS ? 'https' : 'http'}://${customHost}`;
    
    const configUrl = `${baseUrl}/config?uuid=${config.userID}`;
    const proxyUrl = `${baseUrl}/proxy?uuid=${config.userID}`;
    
    const subscription = [
      `#! 更新时间: ${new Date().toISOString()}`,
      `#! UUID: ${config.userID}`,
      '',
      `proxies:`,
      `  - name: ${customHost}`,
      `    type: vmess`,
      `    server: ${customHost}`,
      `    port: 443`,
      `    uuid: ${config.userID}`,
      `    alterId: 0`,
      `    cipher: auto`,
      `    udp: true`,
      `    tls: true`,
      `    skip-cert-verify: ${config.allowInsecure}`,
      `    network: ws`,
      `    ws-path: /?ed=2560`,
      `    ws-headers:`,
      `      Host: ${customHost}`,
      '',
      `proxy-groups:`,
      `  - name: Proxy`,
      `    type: select`,
      `    proxies:`,
      `      - $
