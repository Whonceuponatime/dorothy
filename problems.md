# SUBNET CHECKING
Let me explain the problem and solution:

The main issue was in the `GetMacAddressAsync` method in NetworkStorm.cs (lines 147-199). There were two problems:

1. Variable name conflicts: The same variable names (`macAddr`, `macAddrLen`, `result`) were being used in both the gateway MAC lookup and target MAC lookup sections of the code. In C#, you can't declare variables with the same name in the same scope, even in different if/else blocks.

2. Cross-subnet MAC resolution: When trying to get the MAC address of a device on a different subnet (like 192.168.1.2 from 192.168.0.1), we need to get the gateway's MAC address instead of trying to get the target's MAC directly.

The solution involved:

1. Renaming variables to be unique:
- Gateway section: `gatewayMacAddr`, `gatewayMacAddrLen`, `gatewayResult`
- Target section: `targetMacAddr`, `targetMacAddrLen`, `targetResult`

2. Proper subnet checking and gateway MAC resolution:
```csharp
startLine: 156
endLine: 177
```

This code now properly handles cross-subnet communication by:
- Detecting when the target is on a different subnet
- Getting the gateway's MAC address instead of trying to get the target's MAC directly
- Using the gateway's MAC for packet routing while maintaining the original target IP

This allows your application to conduct tests across subnets as long as there's a route to the target through the gateway.

# END OF SUBNET CHECKING

# RATE LIMITING

