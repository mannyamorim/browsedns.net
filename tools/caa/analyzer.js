function createNode(element) {
    return document.createElement(element);
}

function append(parent, el) {
    return parent.appendChild(el);
}

function locateCAARecordSet(domain) {
    document.getElementById("imgLoading").style.display = "";
    document.getElementById("imgCheckmarkGreen").style.display = "none";
    document.getElementById("imgCheckmarkOrange").style.display = "none";
    document.getElementById("imgRedX").style.display = "none";
    const url = 'https://api.browsedns.net/api/v1/caa?name=' + domain;
    fetch(url)
        .then((resp) => resp.json())
        .then(function (data) {
            document.getElementById("imgLoading").style.display = "none";
            if (data.headers.authenticData) {
                document.getElementById("imgCheckmarkGreen").style.display = "";
            } else {
                document.getElementById("imgCheckmarkOrange").style.display = "";
            }

            var caaRecordsFound = false;
            if (data.records == null || data.records.length == 0) {
                caaRecordsFound = false;
            } else {
                caaRecordsFound = true;
            }

            if (caaRecordsFound == false) {
                var parsed = psl.parse(domain);
                if (parsed.subdomain == null) {
                    displayRecords(null, domain, data);
                    document.getElementById("imgLoading").style.display = "none";
                    document.getElementById("imgCheckmarkGreen").style.display = "none";
                    document.getElementById("imgCheckmarkOrange").style.display = "none";
                    document.getElementById("imgRedX").style.display = "";
                    return null;
                }

                var parts = parsed.subdomain.split('.');
                if (parts.length == 0) {
                    return locateCAARecordSet(parsed.domain);
                } else {
                    var lowestSubdomain = parts.shift();
                    var remainingSubdomain = parts.join('.');
                    var fullDomain = ((parts.length > 0) ? remainingSubdomain + "." : "") + parsed.domain;
                    return locateCAARecordSet(fullDomain);
                }
            } else {
                var records = data.records;
                displayRecords(records, domain, data);
            }
        })
        .catch(function (error) {
            document.getElementById("imgLoading").style.display = "none";
            document.getElementById("imgCheckmarkGreen").style.display = "none";
            document.getElementById("imgCheckmarkOrange").style.display = "none";
            document.getElementById("imgRedX").style.display = "";
            console.log(error);
        });
}

function displayRecords(records, domain, dnsResponse) {
    const recordBlock = document.getElementById('recordsFound');
    if (dnsResponse.headers.authenticData) {
        recordBlock.innerHTML = '; Response was validated with DNSSEC\n';
    } else {
        recordBlock.innerHTML = '; Response was NOT validated with DNSSEC\n';
    }
    if (records == null) {
        recordBlock.innerHTML += 'No CAA Records Found\n';
        displayRecordInfo([], domain);
    } else {
        records.forEach(function (element, index, array) {
            recordBlock.innerHTML += `${domain} IN CAA ${element.flags} ${element.tag} "${element.value}"\n`;
        });
        displayRecordInfo(records, domain);
    }
}

function displayRecordInfo(records, domain) {
    var issue = [];
    var issuewild = [];
    var iodef = [];

    records.forEach(function (element, index, array) {
        var flag = element.flags;
        var type = element.tag;
        var value = element.value;

        switch (type) {
            case "issue":
                issue.push(value);
                break;
            case "issuewild":
                issuewild.push(value);
                break;
            case "iodef":
                iodef.push(value);
                break;
            default:
                console.log("UNKNOWN CAA TAG TYPE");
        }
    });

    var standard = [];
    var wildcard = [];
    var both = [];

    if (issuewild.length == 0) {
        issue.forEach(function (element, index, array) {
            if (element != "\\;") {
                var ca = getCertificateAuthorityName(element.replace(/['"]+/g, ''));
                both.push(ca);
            }
        });
    } else {
        issue.forEach(function (element, index, array) {
            if (element != "\\;") {
                var ca = getCertificateAuthorityName(element.replace(/['"]+/g, ''));
                if (issuewild.indexOf(element) > -1) {
                    both.push(ca);
                } else {
                    standard.push(ca);
                }
            }
        });
        issuewild.forEach(function (element, index, array) {
            if (element != "\\;") {
                var ca = getCertificateAuthorityName(element.replace(/['"]+/g, ''));
                if (issue.indexOf(element) == -1) {
                    wildcard.push(ca);
                }
            }
        });
    }

    standard.sort();
    wildcard.sort();
    both.sort();

    const standardDiv = document.getElementById('standardCA');
    if (standard.length == 0) {
        if (issue.length == 0) {
            standardDiv.innerHTML = 'No Certificate Authorities specified in this category.\nALL Certificate Authorities may issue.';
        } else {
            standardDiv.innerHTML = 'No Certificate Authorities specified in this category.\nNO Certificate Authorities may issue.';
        }
    } else {
        standardDiv.innerHTML = '';
        let ul = createNode('ul');
        append(standardDiv, ul);
        standard.forEach(function (element, index, array) {
            let li = createNode('li');
            let span = createNode('span');
            span.innerHTML = `${element}`;
            append(li, span);
            append(ul, li);
        });
    }

    const wildcardDiv = document.getElementById('wildcardCA');
    if (wildcard.length == 0) {
        if (issue.length == 0 && issuewild.length == 0) {
            wildcardDiv.innerHTML = 'No Certificate Authorities specified in this category.\nALL Certificate Authorities may issue.';
        } else {
            wildcardDiv.innerHTML = 'No Certificate Authorities specified in this category.\nNO Certificate Authorities may issue.';
        }
    } else {
        wildcardDiv.innerHTML = '';
        let ul = createNode('ul');
        append(wildcardDiv, ul);
        wildcard.forEach(function (element, index, array) {
            let li = createNode('li');
            let span = createNode('span');
            span.innerHTML = `${element}`;
            append(li, span);
            append(ul, li);
        });
    }

    const bothDiv = document.getElementById('bothCA');
    if (both.length == 0) {
        if (issue.length == 0 && issuewild.length == 0) {
            bothDiv.innerHTML = 'No Certificate Authorities specified in this category.\nALL Certificate Authorities may issue.';
        } else {
            bothDiv.innerHTML = 'No Certificate Authorities specified in this category.\nNO Certificate Authorities may issue.';
        }
    } else {
        bothDiv.innerHTML = '';
        let ul = createNode('ul');
        append(bothDiv, ul);
        both.forEach(function (element, index, array) {
            let li = createNode('li');
            let span = createNode('span');
            span.innerHTML = `${element}`;
            append(li, span);
            append(ul, li);
        });
    }
}

function search() {
    let domain = document.getElementById('domainInput').value;
    locateCAARecordSet(domain);
    return false;
}