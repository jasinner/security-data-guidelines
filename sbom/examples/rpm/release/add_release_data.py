import json
import sys

from packageurl import PackageURL

# With help from https://security.access.redhat.com/data/meta/v1/repository-to-cpe.json
product_map = {
    "openshift-pipelines-client-1.14.3-11352.el8": [
        {
            "SPDXID": "SPDXRef-OpenShift-Pipelines-1.15-RHEL-8",
            "name": "Red Hat OpenShift Pipelines",
            "versionInfo": "1.15-RHEL-8",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:openshift_pipelines:1.15::el8",
                    "referenceType": "cpe22Type",
                }
            ],
        }
    ],
    "openssl-3.0.7-18.el9_2": [
        # product_versions/1884/variants/4138
        {
            "SPDXID": "SPDXRef-AppStream-9.2.0.Z.EUS",
            "name": "Red Hat Enterprise Linux",
            "versionInfo": "9.2.0.Z.EUS",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:rhel_eus:9.2::appstream",
                    "referenceType": "cpe22Type",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-BaseOS-9.2.0.Z.EUS",
            "name": "Red Hat Enterprise Linux",
            "versionInfo": "9.2.0.Z.EUS",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/o:redhat:rhel_eus:9.2::baseos",
                    "referenceType": "cpe22Type",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-BaseOS-9.2.0.Z.E4S",
            "name": "Red Hat Enterprise Linux",
            "versionInfo": "9.2.0.Z.E4S",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/o:redhat:rhel_e4s:9.2::baseos",
                    "referenceType": "cpe22Type",
                }
            ],
        },
    ],
    "poppler-21.01.0-19.el9": [
        # product_versions/2063/variants/4424
        {
            "SPDXID": "SPDXRef-AppStream-9.4.0.GA",
            "name": "Red Hat Enterprise Linux",
            "versionInfo": "9.4.0.GA",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:enterprise_linux:9::appstream",
                    "referenceType": "cpe22Type",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-CRB-9.4.0.GA",
            "name": "Red Hat Enterprise Linux",
            "versionInfo": "9.4.0.GA",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:enterprise_linux:9::crb",
                    "referenceType": "cpe22Type",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-AppStream-9.4.0.Z.EUS",
            "name": "Red Hat Enterprise Linux",
            "versionInfo": "9.4.0.Z.EUS",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:rhel_eus:9.4::appstream",
                    "referenceType": "cpe22Type",
                }
            ],
        },
    ],
}


repo_id_map = {
    # https://access.redhat.com/downloads/content/openshift-pipelines-client/1.15.0-11496.el8/x86_64/fd431d51/package
    "openshift-pipelines-client-1.14.3-11352.el8": ["pipelines-1.14-for-rhel-8-{arch}-rpms"],
    # https://access.redhat.com/downloads/content/openssl/3.0.7-18.el9_2/x86_64/fd431d51/package
    "openssl-3.0.7-18.el9_2": [
        "rhel-9-for-{arch}-baseos-eus-rpms",
        "rhel-9-for-{arch}-baseos-aus-rpms",
        "rhel-9-for-{arch}-baseos-e4s-rpms",
    ],
    # https://access.redhat.com/downloads/content/poppler/21.01.0-19.el9/x86_64/fd431d51/package
    "poppler-21.01.0-19.el9": [
        "rhel-9-for-{arch}-appstream-rpms",
        "rhel-9-for-{arch}-baseos-eus-rpms",
        "rhel-9-for-{arch}-baseos-aus-rpms",
        "rhel-9-for-{arch}-baseos-e4s-rpms",
    ],
}


def get_rpm_purl(ext_refs):
    purl_str = next(
        (ref["referenceLocator"] for ref in ext_refs if ref["referenceType"] == "purl"),
        None,
    )
    print(purl_str)
    if purl_str is None or (not purl_str.startswith("pkg:rpm/redhat")):
        return None
    return PackageURL.from_string(purl_str)


sbom_file = sys.argv[1]
sbom_name = sbom_file.rsplit("/", 1)[-1].removesuffix(".spdx.json")

if sbom_name not in repo_id_map:
    print(f"ERROR: Repo ID mapping for {sbom_name} not defined!")
    sys.exit(1)

with open(sbom_file) as fp:
    sbom = json.load(fp)

all_arches = set()
for pkg in sbom["packages"]:
    purl = get_rpm_purl(pkg.get("externalRefs", []))
    if purl is not None and purl.qualifiers["arch"] != "src":
        all_arches.add(purl.qualifiers["arch"])

for pkg in sbom["packages"]:
    purl = get_rpm_purl(pkg.get("externalRefs", []))
    if purl is None:
        continue

    new_refs = []
    for repo_id in repo_id_map[sbom_name]:
        if purl.qualifiers["arch"] == "src":
            for arch in all_arches:
                purl.qualifiers["repository_id"] = (
                    repo_id.format(arch=arch).removesuffix("-rpms") + "-source-rpms"
                )
                release_ref = {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl.to_string(),
                }
                new_refs.append(release_ref)
        else:
            if purl.name.endswith("-debugsource"):
                repo_id = repo_id.removesuffix("-rpms") + "-source-rpms"
            elif purl.name.endswith("-debuginfo"):
                repo_id = repo_id.replace("-rpms", "-debug-rpms")
            purl.qualifiers["repository_id"] = repo_id.format(arch=purl.qualifiers["arch"])
            release_ref = {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl.to_string(),
            }
            new_refs.append(release_ref)

    pkg["externalRefs"] = sorted(new_refs, key=lambda ref: ref["referenceLocator"])

if sbom_name in product_map:
    sbom["packages"].extend(product_map[sbom_name])
    product_spdxids = set()
    for product_package in product_map[sbom_name]:
        sbom["relationships"].append(
            {
                "spdxElementId": "SPDXRef-SRPM",
                "relationshipType": "PACKAGE_OF",
                "relatedSpdxElement": product_package["SPDXID"],
            }
        )

with open(f"{sbom_name}.spdx.json", "w") as fp:
    # Add an extra newline at the end since a lot of editors add one when you save a file,
    # and these files get opened and read in editors a lot.
    fp.write(json.dumps(sbom, indent=2) + "\n")
