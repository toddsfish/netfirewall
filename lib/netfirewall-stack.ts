import * as cdk from '@aws-cdk/core';
import * as ec2 from '@aws-cdk/aws-ec2';
import { AmazonLinuxImage, InstanceType } from '@aws-cdk/aws-ec2';
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
    new ec2.Instance(this, 'Instance', {
      vpc: inspectionVpc,
      instanceType: new InstanceType('t2.micro'), 
      machineImage: new AmazonLinuxImage
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

