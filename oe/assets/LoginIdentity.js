// SPDX-License-Identifier: MIT
.pragma library

function qualified(input, realm, workgroup, domainAccount) {
    const name = input.trim();
    if (!domainAccount)
        return /^[A-Za-z_][A-Za-z0-9_.-]*\$?$/.test(name) ? name : "";
    if (typeof realm !== "string" ||
        !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(realm))
        return "";
    const shortName = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
    const downlevel = name.split("\\");
    if (downlevel.length === 2) {
        if (typeof workgroup !== "string" ||
            downlevel[0].toUpperCase() !== workgroup.toUpperCase() ||
            !shortName.test(downlevel[1]))
            return "";
        return downlevel[1] + "@" + realm.toLowerCase();
    }
    const parts = name.split("@");
    if (!shortName.test(parts[0]) || parts.length > 2)
        return "";
    if (parts.length === 2 && parts[1].toLowerCase() !== realm.toLowerCase())
        return "";
    return parts[0] + "@" + realm.toLowerCase();
}
