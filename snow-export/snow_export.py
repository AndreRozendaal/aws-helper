from jinja2 import (
    Environment,
    FileSystemLoader,
    exceptions,
)  # for using jinja2 templates
import xml.dom.minidom  # for checking if the xm is valid
import boto3
import json
import sys
import datetime
from typing import List, Dict, Optional
from enum import Enum

boto3.setup_default_session(profile_name="sandbox")

# us-east-1 is where the pricing api is. Don't modify the following line
# This region does not align to the region where the target EC2 instance lives
pricing_client = boto3.client("pricing", region_name="us-east-1")
ssm_client = boto3.client("ssm")
ec2_resource = boto3.resource("ec2")


def get_all_ec2_volumes() -> List[Dict]:
    """Get all ec2 volumes

    Returns: a list with dicts with the following keys: id, state, instance and create_time of the volume.
    """

    volumes = []
    volume_iterator = ec2_resource.volumes.all()
    for v in volume_iterator:
        for a in v.attachments:
            volume = ec2_resource.Volume(v.id)
            volumes.append(
                {
                    "id": v.id,
                    "state": v.state,
                    "instance": a["InstanceId"],
                    "create_time": volume.create_time.isoformat(),
                }
            )
    return volumes


def sanitize(input) -> str:
    """ Sanitize input string to remove whitespace and make it lowercase """
    return input.strip().lower()

class Product(Enum):
    PRODUCT_LINUX = "linux"
    PRODUCT_WINDOWS = "windows"
    PRODUCT_WINDOWSBYOL = "windowsbyol"
    PRODUCT_ENTERPRISE = "enterprise"
    PRODUCT_STANDARD = "standard"
    PRODUCT_WEB = "web"


def interpretProductVersion(productVersion: str) -> Optional[str]:
    switcher = {
        Product.PRODUCT_LINUX.value: Product.PRODUCT_LINUX.value,
        "l": Product.PRODUCT_LINUX.value,
        "lin": Product.PRODUCT_LINUX.value,
        Product.PRODUCT_ENTERPRISE.value: Product.PRODUCT_ENTERPRISE.value,
        "e": Product.PRODUCT_ENTERPRISE.value,
        "ent": Product.PRODUCT_ENTERPRISE.value,
        "standard": Product.PRODUCT_STANDARD.value,
        "s": Product.PRODUCT_STANDARD.value,
        "std": Product.PRODUCT_STANDARD.value,
        Product.PRODUCT_WINDOWS.value: Product.PRODUCT_WINDOWS.value,
        "w": Product.PRODUCT_WINDOWS.value,
        "win": Product.PRODUCT_WINDOWS.value,
        Product.PRODUCT_WINDOWSBYOL.value: Product.PRODUCT_WINDOWSBYOL.value,
        "wb": Product.PRODUCT_WINDOWSBYOL.value,
        "winBYOL": Product.PRODUCT_WINDOWSBYOL.value,
        "BYOL": Product.PRODUCT_WINDOWSBYOL.value,
        Product.PRODUCT_WEB.value: Product.PRODUCT_WEB.value,
        "wb": Product.PRODUCT_WEB.value,
    }
    return switcher.get(productVersion)


def getProductBillingCode(productVersion):
    productVersion = sanitize(productVersion)
    productVersion = interpretProductVersion(productVersion)
    switcher = {
        Product.PRODUCT_LINUX.value: "RunInstances",
        Product.PRODUCT_ENTERPRISE.value: "RunInstances:0102",
        Product.PRODUCT_STANDARD.value: "RunInstances:0006",
        Product.PRODUCT_WINDOWS.value: "RunInstances:0002",
        Product.PRODUCT_WINDOWSBYOL.value: "RunInstances:0800",
        Product.PRODUCT_WEB.value: "RunInstances:0202",
    }
    return switcher.get(productVersion)


def get_ec2_pricing_info(instance_type:str, platformType:str):
    billingCode = getProductBillingCode(platformType)
    product_pager = pricing_client.get_paginator("get_products")
    product_iterator = product_pager.paginate(
        ServiceCode="AmazonEC2",
        Filters=[
            {"Type": "TERM_MATCH", "Field": "capacityStatus", "Value": "Used"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": "EU (Ireland)"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "operation", "Value": billingCode},
        ],
    )

    for product_item in product_iterator:
        for offer_string in product_item.get("PriceList"):
            offer = json.loads(offer_string)
            product = offer.get("product")
            product_attributes = product.get("attributes")

            ec2data = {}
            ec2data["sku"] = product["sku"]
            ec2data["memory"] = product_attributes["memory"]
            ec2data["vcpu"] = product_attributes["vcpu"]
            ec2data["operatingSystem"] = product_attributes["operatingSystem"]
            ec2data["regionCode"] = product_attributes["regionCode"]
            ec2data["physicalProcessor"] = product_attributes["physicalProcessor"]
            ec2data["clockSpeed"] = product_attributes["clockSpeed"]
            ec2data["tenancy"] = product_attributes["tenancy"]
            ec2data["processorFeatures"] = product_attributes["processorFeatures"]
            ec2data["processorArchitecture"] = product_attributes[
                "processorArchitecture"
            ]

            return ec2data


def get_ec2_instances() -> List[Dict]:
    instances = []
    pager = ssm_client.get_paginator("describe_instance_information")
    iterator = pager.paginate()
    for item in iterator:
        instanceInfoList = item["InstanceInformationList"]
        for info in instanceInfoList:
            instancedata = {}
            instancedata["InstanceId"] = info["InstanceId"]
            instancedata["AgentVersion"] = info["AgentVersion"]
            instancedata["PlatformType"] = info["PlatformType"]
            instancedata["PlatformName"] = info["PlatformName"]
            instancedata["PlatformVersion"] = info["PlatformVersion"]
            instancedata["IPAddress"] = info["IPAddress"]
            instances.append(instancedata)

    return instances

def get_ec2_inventory_entries(instanceId, typeName):
    inventory = []
    response = ssm_client.list_inventory_entries(
        InstanceId=instanceId, TypeName=typeName
    )

    entries = response["Entries"]
    while "NextToken" in response:
        response = ssm_client.list_inventory_entries(
            InstanceId=instanceId,
            TypeName=typeName,
            NextToken=response["NextToken"],
        )
        entries.extend(response["Entries"])
    captureTime = response.get("CaptureTime")
    if not captureTime:
        captureTime = "1900-01-01T12:00:00.000000+00:0"

    for item in entries:
        inventory.append(item)
    return inventory


def get_account_id() -> str:
    return boto3.client("sts").get_caller_identity()["Account"]


def get_ec2_instance_details(instanceId:str) -> Dict:
    instance = ec2_resource.Instance(instanceId)
    instancedata = {}
    instancedata["instance_type"] = instance.instance_type
    instancedata["image_id"] = instance.image_id
    instancedata["architecture"] = instance.architecture
    return instancedata


def getOSManufacturer(productVersion: str) -> Optional[str]:
    productVersion = sanitize(productVersion)

    # This part needs to be adjusted to support other vendors
    switcher = {Product.PRODUCT_LINUX.value: "Amazon Inc.", Product.PRODUCT_WINDOWS.value: "Microsoft Corporation"}
    return switcher.get(productVersion)


def convertGiB2MB(memory: str) -> int:
    memory = memory.replace(" GiB", "")
    return int(memory) * 1024 * 1024 * 1024


def main():
    volumes = get_all_ec2_volumes()

    ec2_instances = get_ec2_instances()
    if len(ec2_instances) == 0:
        print("No EC2 instances found")
        sys.exit(2)
    else:
        print("Found " + str(len(ec2_instances)) + " EC2 instances")
    snowdatas = []

    for ec2_instance in ec2_instances:

        instanceId = ec2_instance["InstanceId"]  # we need one ec2 instance for api data
        instancedata = get_ec2_instance_details(ec2_instance["InstanceId"])

        print(f"{instanceId} ({instancedata['instance_type']}) Gathering data...")
        ec2_pricing_data = get_ec2_pricing_info(
            instancedata["instance_type"], ec2_instance["PlatformType"]
        )

        # https://github.com/awsdocs/aws-systems-manager-user-guide/blob/main/doc_source/sysman-inventory-schema.md
        inventoryDetailedInfo = get_ec2_inventory_entries(
            instanceId, "AWS:InstanceDetailedInformation"
        )
        inventoryNetworking = get_ec2_inventory_entries(instanceId, "AWS:Network")
        inventory = get_ec2_inventory_entries(instanceId, "AWS:Application")

        snowdata = {}
        snowdata["lastupdate"] = datetime.datetime.now().isoformat()
        snowdata["hostname"] = ec2_instance["InstanceId"]
        snowdata["clientidentifier"] = snowdata["hostname"]
        snowdata["site"] = "site"  # To be aligned within Snow Software
        snowdata["manufacturer"] = "AWS"
        snowdata["biosserialnumber"] = snowdata["hostname"]
        snowdata["model"] = instancedata["instance_type"]
        snowdata["clienttype"] = ec2_pricing_data[
            "operatingSystem"
        ]  # Types allowed = Windows, Mac OS X, Red Hat Linux, Linux, HP-UX, Solaris, AIX, ESX
        snowdata["isvirtual"] = True
        snowdata["hypervisorname"] = "xen"  # Use the proper hypervisor
        snowdata["notebook"] = False
        snowdata["ismobiledevice"] = False

        snowdata["processors"] = inventoryDetailedInfo[0]["CPUCores"]
        snowdata["processorname"] = inventoryDetailedInfo[0]["CPUModel"]
        snowdata["coresperprocessor"] = inventoryDetailedInfo[0]["CPUs"]
        snowdata["processorspeed"] = inventoryDetailedInfo[0]["CPUSpeedMHz"]
        snowdata["processormodel"] = inventoryDetailedInfo[0]["CPUModel"]
        snowdata["memory"] = convertGiB2MB(ec2_pricing_data["memory"])
        snowdata["ipaddress"] = inventoryNetworking[0]["IPV4"]
        snowdata["macaddress"] = inventoryNetworking[0]["MacAddress"]
        snowdata["osname"] = ec2_instances[0]["PlatformName"]
        snowdata["osversion"] = ec2_instances[0]["PlatformVersion"]
        snowdata["osbuild"] = ec2_instances[0]["PlatformVersion"]
        snowdata["osmanufacturer"] = getOSManufacturer(ec2_instances[0]["PlatformType"])

        for v in volumes:
            if v["instance"] == instanceId:
                snowdata["installdate"] = v["create_time"]

        inv = []

        for item in inventory:
            inv.append(
                {
                    "InstallDate": item["InstalledTime"],
                    "Manufacturer": item["Publisher"],
                    "Application": item["Name"],
                    "Version": item["Version"],
                }
            )

        snowdata["software"] = inv
        snowdatas.append(snowdata)

    j2_env = Environment(loader=FileSystemLoader("."), trim_blocks=True)
    for snowdata in snowdatas:
        try:
            xml_file = j2_env.get_template("xml_template.xml").render(
                snowdata=snowdata,
            )
        except exceptions.TemplateNotFound:
            print("Template not found")
            sys.exit(2)
        try:
            xml.dom.minidom.parseString(xml_file)
        except xml.parsers.expat.ExpatError as error:
            print(f"{snowdata['hostname']}: XML is invalid: {error}")
            raise (error)

        filename = f"{get_account_id()}_{snowdata['hostname']}.xml"
        with open(filename, "w") as f:
            print(f"Writing {snowdata['hostname']} to {filename}")
            f.write(xml_file)


if __name__ == "__main__":
    main()
