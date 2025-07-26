# GoMITMProxy

A flexible HTTP proxy library for Go with built-in Man-in-the-Middle (MITM) capabilities. This library enables you to create both forward and reverse proxies with the ability to intercept, inspect, and modify HTTP/HTTPS traffic.

## Features

- 🔄 **Forward Proxy**: Route HTTP/HTTPS requests through the proxy
- 🔁 **Reverse Proxy**: Act as a reverse proxy for specific targets
- 🔐 **MITM Support**: Intercept and decrypt HTTPS traffic
- 📋 **Certificate Management**: Automatic certificate generation and caching
- 🎯 **Request/Response Interception**: Modify requests and responses on-the-fly
- ⚙️ **Configurable**: Customizable timeouts, connection limits, and TLS settings
- 🛡️ **Connect Handling**: Flexible CONNECT request handling (Accept/Reject/MITM)

## License

[MIT](LICENSE)

## Security Notice

This library is designed for development, testing, and debugging purposes. Use MITM capabilities responsibly and ensure you have proper authorization when intercepting network traffic.
