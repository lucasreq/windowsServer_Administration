Param (
    [parameter(Mandatory=$true)][string]$mode
)

Import-Module activedirectory
Import-Module psexcel
Import-Module FileServerResourceManager

$path = "C:\Users\Administrateur\Downloads\UsersAD.xlsx"

$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$netbios = (Get-ADDomain).NetBIOSName
$server = (Get-WmiObject Win32_ComputerSystem).Name
$fqdn = "{0}.{1}" -f $server, $domain
$DN = (Get-ADDomain).DistinguishedName

$ParentHomesFolderName = "Users$"
$LocalParentHomeFolder = "C:\storage\users\"
$RemoteParentHomesFolder = "\\{0}\{1}\" -f $server, $ParentHomesFolderName
$FullAccess = "$($netbios)\Utilisateurs du domaine"

$ParentShareFolderName = "Share"
$LocalParentShareFolder = "C:\storage\share\"
$RemoteParentShareFolder = "\\{0}\{1}\" -f $server, $ParentShareFolderName

if ($mode -like "OU") {
    foreach($person in (Import-XLSX -Path $path -RowStart 1)) {

        $OU = "OU={0},OU={1},OU=Etudiants,{2}" -f $person.AnneeDemarrage, $person.Cycle, $DN
        $OU2 = "OU={0},OU=Etudiants,{1}" -f $person.Cycle, $DN

        if (($domain -like $person.Domaine) -and (!(Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$OU2'"))) {
           try {
                New-ADOrganizationalUnit -Name $person.Cycle -Path $DN
                echo "Création de : " $person.Cycle
            } catch {
                echo "Erreur création : " $person.Cycle
            }
        }
     
    }

    foreach($person in (Import-XLSX -Path $path -RowStart 1)) {

        $OU = "OU={0},OU={1},OU=Etudiants,{2}" -f $person.AnneeDemarrage, $person.Cycle, $DN
        $OU2 = "OU={0},OU=Etudiants,{1}" -f $person.Cycle, $DN

        if (($domain -like $person.Domaine) -and (!(Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$OU'"))) {
            try {
                New-ADOrganizationalUnit -Name $person.AnneeDemarrage -Path $OU2
                echo "Création de : " $person.AnneeDemarrage
            } catch {
                echo "Erreur création : " $person.AnneeDemarrage
            }
        }
    }
}

if ($mode -like "SHARE") {

    if (-not(Test-Path $LocalParentHomeFolder -PathType Container)) {
        New-Item -Path $LocalParentHomeFolder -ItemType Directory
        sleep 2
    }

    try {
        New-SMBShare –Name "$ParentHomesFolderName" –Path "$LocalParentHomeFolder" –FullAccess $FullAccess, "Système"
        sleep 2

    } catch {
        echo "Le partage de fichier pour les sessions utilisateurs n'a pas pu être créé ou il existe déjà."
    }

    if (-not(Test-Path $LocalParentShareFolder -PathType Container)) {
        New-Item -Path $LocalParentShareFolder -ItemType Directory
        sleep 2
    }

    try {
        New-SMBShare –Name $ParentShareFolderName –Path $LocalParentShareFolder –FullAccess $FullAccess,"Système"
        sleep 2

    } catch {
        echo "Le partage de fichier pour les classes n'a pas pu être créé ou il existe déjà."
    }

    try {
    New-FsrmQuotaTemplate -Name "HomeFolder" -Description "limit usage to 50 MB for home folder." -Size 50MB
    } catch {echo "Le template HomeFolder existe"}
    try {
    New-FsrmQuotaTemplate -Name "ShareFolder" -Description "limit usage to 100 MB for share folder." -Size 100MB
    } catch {echo "Le template ShareFolder existe"}
}


if ($mode -like "USERS") {

    $classes = [System.Collections.ArrayList]@()

    foreach($person in (Import-XLSX -Path $path -RowStart 1)) {

        $OUusers = "OU={0},OU={1},OU=Etudiants,{2}" -f $person.AnneeDemarrage, $person.Cycle, $DN
        $login = $person.Prenom.Substring(0,1).ToLower() + $person.NOM.ToLower()
        $name = "{0} {1}" -f $person.Prenom, $person.NOM
        $email = "{0}@{1}" -f $login, $person.Domaine
        $password=(ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)

        $RemoteHomeFolder = $RemoteParentHomesFolder + $login
        $LocalHomeFolder = $LocalParentHomeFolder + $login

        $classe = "{0}-{1}" -f $person.Cycle, $person.AnneeDemarrage

        $LocalShareFolder = $LocalParentShareFolder + $classe
        $RemoteShareFolder = $RemoteParentShareFolder + $classe

        $checkClasse = Get-ADGroup -LDAPFilter "(SAMAccountName=$classe)"

        if ( $domain -like $person.Domaine) {
            if (!($classes.Contains($classe))){

                $classes.Add($classe)
                New-Variable -Name "$($classe)_manager" -Value $login -Force
            }

            if (-not(Test-Path $LocalHomeFolder -PathType Container)) {
                New-Item -Path $LocalHomeFolder -ItemType Directory
                sleep 1
                New-FsrmQuota -Path $LocalHomeFolder -Description "Limitation de stockage de 50MB pour le dossier utilisateur $login" -Template "HomeFolder"
            }

            if ($checkClasse -eq $null) {
                New-ADUser -Name $name -AccountPassword $password -City $person.NomEtablissement -Company $person.NomEtablissement -Department $person.Cycle -DisplayName $name -Division $person.AnneeDemarrage -EmailAddress $email -Enabled $true -GivenName $person.Prenom -HomeDirectory $RemoteHomeFolder -HomeDrive "U" -PasswordNeverExpires $true -Path $OUusers -SamAccountName $login -UserPrincipalName $login -Office $classe -passThru
                echo "Création du délégué : $name"
                sleep 1
                New-ADGroup -GroupScope 1 -Name $classe -Description "$classe students" -DisplayName $classe -GroupCategory 1 -ManagedBy "$((Get-Variable -Name "$($classe)_manager").Value)" -Path $OUusers -SamAccountName $classe -passThru
                echo "Création de la classe : $classe"
            } else {
                New-ADUser -Name $name -AccountPassword $password -City $person.NomEtablissement -Company $person.NomEtablissement -Department $person.Cycle -DisplayName $name -Division $person.AnneeDemarrage -EmailAddress $email -Enabled $true -GivenName $person.Prenom -HomeDirectory $RemoteHomeFolder -HomeDrive "U" -PasswordNeverExpires $true -Path $OUusers -SamAccountName $login -UserPrincipalName $login -Office $classe -Manager $((Get-Variable -Name "$($classe)_manager").Value) -passThru
            }

            if (-not(Test-Path $LocalShareFolder -PathType Container)) {
                New-Item -Path $LocalShareFolder -ItemType Directory
                New-FsrmQuota -Path $LocalShareFolder -Description "Limitation de stockage de 100Mo pour le dossier partagé de la classe $classe" -Template "ShareFolder"
                sleep 1
                $ACL = Get-ACL -Path $LocalShareFolder
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Système", "FullControl","ContainerInherit, ObjectInherit", "None", "Allow")
                $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$netbios\$classe", "Modify","ContainerInherit, ObjectInherit", "None", "Allow")
                $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("$netbios\$classe", "AppendData","ContainerInherit, ObjectInherit", "None", "Allow")
                $ACL.SetAccessRule($rule)
                $ACL.AddAccessRule($rule1)
                $ACL.AddAccessRule($rule2)
                Set-ACL -path $LocalShareFolder -AclObject $ACL
            }

            Add-ADGroupMember -Identity $classe -Members $login

            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$netbios\$login", "FullControl","ContainerInherit, ObjectInherit", "None", "Allow")

            $ACL = Get-ACL -Path $RemoteHomeFolder
            $ACL.SetAccessRule($rule)
            Set-ACL -path $RemoteHomeFolder -AclObject $ACL
        }
    }
}