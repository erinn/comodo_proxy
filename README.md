comodo_proxy is a simle(ish) proxy between Comodo's SOAP API and a custom and minimal REST API. comodo_proxy
is designed to be deployed in a Kerberos/GSSAPI environment as access control is handled via principles, the code
could be modified for simple auth easily. 

# Deploying:
This code is meant to be run inside of a docker container, and for maximum ease I would recommend using the 
source-to-image tool: https://github.com/openshift/source-to-image

Using s2i will dramatically speed up deployment of the application, if a container needs to be built by hand 
for some reason, that exercise will be left up to the reader.

To build the image run the following for CentOS:

    s2i build https://github.com/erinn/comodo_proxy docker.io/centos/python-36-centos7 comodo_proxy:latest

Or if you have paid for a RHEL system:

    s2i build https://github.com/erinn/comodo_proxy registry.access.redhat.com/rhscl/python-36-rhel7 comodo_proxy:latest

This will provide you with a docker container tagged 'comodo_proxy' which you will then need to start with the
appropriate mount points, see below.

## Mounts:
The container requires the following mounts in order to work (all files on the host must, obviously, 
be readable by the container, the container runs as user 1001:0 set permissions accordingly):
- /etc/krb5.keytab:/etc/krb5.keytab:ro
The keytab to be used, another source location can be used if needed( for instance /etc/keytabs/krb5-HTTP.keytab) but 
/etc/krb5.keytab should be where it is mapped to in the container for ease. The keytab should not be world readable
so chgrp it to 0 mode 640 and note the SELinux section below.
- /etc/krb5.conf:/etc/krb5.conf:ro The krb5.conf file to let kerberos know how to operate
-/etc/pki/tls/certs/comodo_client.crt:/etc/pki/tls/certs/comodo_client.crt:ro If two factor authentication is being used against Comodo's API, the location of the public client certificate.
- /etc/pki/tls/private/comodo_client.key:/etc/pki/tls/private/comodo_client.key:ro If two factor authentication is being used against Comodo's API, the location of the private client key. Again a file that should only be readable by the container user, chgrp to 0 and mode 640.

All mounts are read only, as nothing should change on the host.

### Mounts and SELinux
If you are unfortunate enough to be working in an SELinux environment you MIGHT have to change the context of 
some files, in the above mounts /etc/krb5.keytab would need the context changed to svirt_sandbox_file_t so the container
can read it. Most, but not all files in /etc/ on the host are readable by docker.

There is a bug open about this here: https://bugzilla.redhat.com/show_bug.cgi?id=1532386

## Development:
For ease of use during development, the docker-compose.yml file has been provided with all mounts listed. The image
that is brought up can be placed behind any proxy (nginx, apache, see below). However it is set to trust all headers
by default, this is dangerous and should only be used for development or in a highly controlled environment.


## Environmental Variables:
The comodo_proxy app consumes all of its configuration via the following environmental variables:
- COMODO_API_URL: The URL for the Comodo API, for example: 'https://hard.cert-manager.com/private/ws/EPKIManagerSSL?wsdl'
- COMODO_CERT_TYPE_NAME: The certificate type name to use for requests for example: 'Comodo Unified Communications Certificate'
- COMODO_CLIENT_CERT_AUTH: Set to 'True' if you need to use client certificate authentication with Comodo.
- COMODO_CLIENT_PUBLIC_CERT: The path to the public certificate in PEM encoded format.
- COMODO_CLIENT_PRIVATE_KEY: The path to the private key.
- COMODO_CUSTOMER_LOGIN_URI: The customer login URI, example 'example-corp'.
- COMODO_LOGIN: The actual login to Comodo, or user name as a synonym.
- COMODO_ORG_ID: The Organization ID given to you by Comodo, example '123456'.
- COMODO_PASSWORD: The password for your login or user name.
- COMODO_REVOKE_PASSWORD: The password to set for revocation of Comodo certificates (does not appear to be used anywhere but Comodo requires it).
- COMODO_SECRET_KEY: Comodo's secret key.
- GSSAPI_HOSTNAME: Because this is run in a container the hostname will not match the kerberos principle and as such needs to be overriden, set this to the kerberos principle's name.
- GSSAPI_SERVICE_NAME: You can select the GSSAPI service name to use here, if omitted HTTP will be used.
- SECRET_KEY: The secret key for flask to encrypt data with.
- DATABASE_URL: A full URL for the database, example: mysql+mysqlconnector://<DB User>:<DB Password>@<DB Host>:<DB Port>/<DB Name>

# The comodo_proxy ACL file:
The 'acl' file, located in /etc/comodo_proxy/acl in the container is simply formatted as one principle per line, for
example:

    api-user@EXAMPLE.COM
    api-user2@EXAMPLE.COM

The first part before the '@' is the user/host/service definition, the second is the Kerberos realm.

# Proxying for the Container:
You will probably not want the container exposing gunicorn, instead a proxy is recommended using either apache or nginx.
A few headers need to be set in order for the application to respond with the correct URLs. The following examples are
using SSL/TLS by default (as that is simply best and should be the default).

For nginx:

    # Settings for a TLS enabled server.
    #
        server {
            listen       443 ssl http2 default_server;
            listen       [::]:443 ssl http2 default_server;
            server_name  _;
            root         /usr/share/nginx/html;
    
            ssl_certificate "/etc/pki/tls/certs/www.example.com.crt";
            ssl_certificate_key "/etc/pki/tls/private/www.example.com.key";
            ssl_session_cache shared:SSL:1m;
            ssl_session_timeout  10m;
            ssl_ciphers PROFILE=SYSTEM;
            ssl_prefer_server_ciphers on;
    
            # Load configuration files for the default server block.
            include /etc/nginx/default.d/*.conf;
    
            location / {
                    proxy_pass         http://localhost:8080/;
                    proxy_redirect     off;
    
                    # Set the host header so gunicorn/flask can consume it and set URLs correctly
                    proxy_set_header   Host                 $host;
                    proxy_set_header   X-Real-IP            $remote_addr;
                    proxy_set_header   X-Forwarded-For      $proxy_add_x_forwarded_for;
                    # Whether to produce http or https URLs
                    proxy_set_header   X-Forwarded-Proto    $scheme;
            }
            
For apache:

    <VirtualHost www.example.com:443>
            SSLEngine On
            ServerName www.example.com
            DocumentRoot /var/www/html/
            ServerAdmin help@example.com
    
            SSLEngine On
            SSLCertificateFile /etc/pki/tls/certs/www.example.com.crt
            SSLCertificateKeyFile /etc/pki/tls/private/www.example.com.key
    
            <Directory /var/www/html/>
                Require all granted
            </Directory>
    
            RequestHeader set X-Forwarded-Proto "https"
            ProxyPreserveHost On
            # For Apache info
            ProxyPass /server-info !
            ProxyPass /server-status !
            # For ACME challenges (LetsEncrypt)
            ProxyPass /.well-known !
            ProxyPass "/" "http://localhost:8080/"
            ProxyPassReverse "/" "http://localhost:8080/"
    </VirtualHost>