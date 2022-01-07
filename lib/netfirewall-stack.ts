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

    // Create Network Firewall
    const netFirewallPolicy = new networkfirewall.CfnFirewallPolicy(this, 'netFirewallPolicy', {
      firewallPolicy: {
        statelessDefaultActions: ['aws:forward_to_sfe'],
        statelessFragmentDefaultActions: ['aws:forward_to_sfe']
      },
      firewallPolicyName: 'netFirewallPolicy',
    });

    const netFirewallStatefulRg = new networkfirewall.CfnRuleGroup(this, 'netFirewallStatefulRg', {
      ruleGroupName: 'netFirewallStatefulRg',
      type: 'STATEFUL',
      capacity: 30000,
      ruleGroup: {
        rulesSource: {
          rulesString: 'pass http $HOME_NET any -> $EXTERNAL_NET 80 (http.host; dotprefix; content:"blog.toddaas.com"; endswith; msg:"Allowed HTTP domain"; priority:1; sid:1; rev:1;)\ndrop tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Drop established non-HTTP to TCP:80"; flow: from_client,established; sid:2; priority:5; rev:1;)\ndrop tcp 10.0.0.0/16 any -> 10.0.0.0/16 22 (msg:"Drop SSH"; sid:3; priority:6; rev:1;)'
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

