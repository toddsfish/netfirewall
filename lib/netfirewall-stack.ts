import * as cdk from '@aws-cdk/core';
import * as ec2 from '@aws-cdk/aws-ec2';
import { AmazonLinuxImage, InstanceType, Peer } from '@aws-cdk/aws-ec2';
import * as networkfirewall from '@aws-cdk/aws-networkfirewall';

export class NetfirewallStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    new InspectionVpcStack(this, 'InspectionVpc');
    //new SpokeVpc(this, "SpokeVpcA");
    //new SpokeVpc(this, "SpokeVpcB");
    //new SpokeVpc(this, "SpokeVpcC");
  }
}

class InspectionVpcStack extends cdk.NestedStack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.NestedStackProps) {
    super(scope, id, props);

    // Create VPC and Subnets
    console.log('Across these AZs')
    console.log(this.availabilityZones);
    const inspectionVpc = new ec2.Vpc(this, 'InspectionVpcStack', {
      cidr: "10.0.0.0/16",
      maxAzs: this.availabilityZones.length,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC
        },
        {
          cidrMask: 24,
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED
        },
        {
          cidrMask: 24,
          name: 'Inspection',
          subnetType: ec2.SubnetType.PRIVATE_WITH_NAT
        }
      ]
    });

    // Create Network Firewall Strict Order
    const netFirewallPolicy = new networkfirewall.CfnFirewallPolicy(this, 'netFirewallPolicy', {
      firewallPolicy: {
        statelessDefaultActions: ['aws:forward_to_sfe'],
        statelessFragmentDefaultActions: ['aws:forward_to_sfe'], 
        statefulEngineOptions: {  
          // Adjust to DEFAULT_ACTION_ORDER (DEFAULT_ACTION_ORDER is the default behavior.) | STRICT_ORDER rules evaluated by order of priority, starting from the lowest number, and the rules in each rule group are processed in the order in which they're defined.
          ruleOrder: 'STRICT_ORDER'
        },
        // The stateful default action is optional, and is only valid when using the strict rule order.
        statefulDefaultActions: ['aws:aws:alert_established']
      },
      firewallPolicyName: 'netFirewallPolicy',
    });

    const netFirewallStatefulRg = new networkfirewall.CfnRuleGroup(this, 'netFirewallStatefulRg', {
      ruleGroupName: 'netFirewallStatefulRg',
      type: 'STATEFUL',
      capacity: 30000,
      ruleGroup: {
        rulesSource: {
          rulesString: 'alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:\"alert HTTP\"; sid:100100; rev:147;)\nalert tls $HOME_NET any <> $EXTERNAL_NET 443 (msg:\"alert TLS\"; sid:100200; rev:147;)\npass http $HOME_NET any -> $EXTERNAL_NET 80 (http.host; dotprefix; content:".toddaas.com"; endswith; msg:"Whitelist HTTP Rule"; sid:100300; rev:147;)\npass http $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; dotprefix; content:".toddaas.com"; endswith; msg:"Whitelist TLS Rule"; sid:100300; rev:147;)'
        },
        statefulRuleOptions: {
          ruleOrder: 'STRICT_ORDER'
        }
      }
    });

    const inspectionSubnets = inspectionVpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_NAT
    });

    const inspectionSubnetMapping = inspectionSubnets.subnets.map(subnet => {
      return {
        subnetId: subnet.subnetId
      }
    });

    const netFirewall = new networkfirewall.CfnFirewall(this, 'netFirewall', {
      firewallName: 'netFirewall',
      firewallPolicyArn: netFirewallPolicy.attrFirewallPolicyArn,
      subnetMappings: inspectionSubnetMapping,
      vpcId: inspectionVpc.vpcId,
    });

    // Create Instances in Public & Private Subnets

    const sgAllowSSH = new ec2.SecurityGroup(this, 'sg-allow-ssh', {
      vpc: inspectionVpc,
      allowAllOutbound: true,
      description: 'Allow ssh access'
    });

    sgAllowSSH.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));

    new ec2.Instance(this, 'Public_Instance', {
      vpc: inspectionVpc,
      instanceType: new InstanceType('t2.micro'), 
      machineImage: new AmazonLinuxImage,
      securityGroup: sgAllowSSH,
      keyName: 'prod-' + this.region + '-keypair',
      vpcSubnets: inspectionVpc.selectSubnets({
        subnetType: ec2.SubnetType.PUBLIC
      })
    });

    new ec2.Instance(this, 'Protected_Instance', {
      vpc: inspectionVpc,
      instanceType: new InstanceType('t2.micro'), 
      machineImage: new AmazonLinuxImage,
      securityGroup: sgAllowSSH,
      keyName: 'prod-' + this.region + '-keypair',
      vpcSubnets: inspectionVpc.selectSubnets({
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED
      })
    });
  }
}

class SpokeVpc extends cdk.NestedStack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.NestedStackProps) {
    super(scope, id, props);

    const spokeVpc = new ec2.Vpc(this, 'SpokeVpcStack', {
      cidr: "10.10.0.0/16",
      natGateways: 0
    });
  }
}

