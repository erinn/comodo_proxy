![](https://github.com/erinn/comodo_proxy/workflows/Container%20Deploy/badge.svg)
    
comodo_proxy is a simple(ish) proxy between Sectigo's REST API and a custom and minimal REST API. comodo_proxy
is designed to be deployed in a Kerberos/GSSAPI environment as access control is handled via principles, the code
could be modified for simple auth easily. 

# Building a container for development use:
This code is meant to be run inside of a docker container, and for maximum ease I would recommend using the 
source-to-image tool: https://github.com/openshift/source-to-image

You will need to have at least version >= 1.3.0 of s2i. 

To build the dockerfile run the following for CentOS:

    s2i generate docker.io/centos/python-36-centos7 Dockerfile

Or if you wish to use the now free to all RHEL UBI containers:

    s2i generate registry.access.redhat.com/ubi8/python-38 Dockerfile

This will provide you with a Dockerfile which you can then run through your preferred builder. Most folks will be most familiar with 'docker build':

    docker build -t comodo_proxy:latest .

However, buildah can also be used:

    buildah build -f Dockerfile -t comodo_proxy:dev .
    
Finally push the container to the appropriate location using docker, buildah, or whatever tool suits you.

## Mounts:
The container requires the following mounts in order to work (all files on the host must, obviously, 
be readable by the container, the container runs as user 1001:0 set permissions accordingly):
- /etc/krb5.keytab:/etc/krb5.keytab:ro
The keytab to be used, another source location can be used if needed( for instance /etc/keytabs/krb5-HTTP.keytab) but 
/etc/krb5.keytab should be where it is mapped to in the container for ease. The keytab should not be world readable
so chgrp it to 0 mode 640 and note the SELinux section below.
- /etc/krb5.conf:/etc/krb5.conf:ro The krb5.conf file to let kerberos know how to operate
- /etc/pki/tls/certs/comodo_client.crt:/etc/pki/tls/certs/comodo_client.crt:ro If two factor authentication is being used against Comodo's API, the location of the public client certificate.
- /etc/pki/tls/private/comodo_client.key:/etc/pki/tls/private/comodo_client.key:ro If two factor authentication is being used against Comodo's API, the location of the private client key. Again a file that should only be readable by the container user, chgrp to 0 and mode 640.

All mounts are read only, as nothing should change on the host.

### Mounts and SELinux
If you are unfortunate enough to be working in an SELinux environment you MIGHT have to develop a custom
policy module to allow access to the kerberos keytab, configuration file, and certificates an example is included below.

There is a bug open about this here: https://bugzilla.redhat.com/show_bug.cgi?id=1532386

    # Only needed until https://bugzilla.redhat.com/show_bug.cgi?id=1532386 is
    # closed
    module docker_kerberos 1.0;
    
    require {
            type krb5_conf_t;
            type krb5_keytab_t;
            type container_t;
            type cert_t;
            class file { getattr lock open read };
    }
    
    #============= container_t ==============
    allow container_t krb5_conf_t:file getattr;
    allow container_t krb5_conf_t:file { open read };
    allow container_t  krb5_keytab_t:file lock;
    allow container_t  krb5_keytab_t:file { open read };
    allow container_t cert_t:file getattr;
    allow container_t cert_t:file { open read };

Place the above into a docker_kerberos.te file, compile it into a module and then insert the module:
 - checkmodule -M -m -o docker_kerberos.mod docker_kerberos.te
 - semodule_package -o docker_kerberos.pp -m docker_kerberos.mod
 - sudo semodule -i docker_kerberos.pp 
 
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
- GSSAPI_HOSTNAME: Because this is run in a container the hostname will not match the kerberos principle and as such needs to be overriden, set this to the kerberos principle's name.
- GSSAPI_SERVICE_NAME: You can select the GSSAPI service name to use here, if omitted HTTP will be used.
- SECRET_KEY: The secret key for flask to encrypt data with.
- DATABASE_URL: A full URL for the database, example: mysql+mysqlconnector://<DB User>:<DB Password>@<DB Host>:<DB Port>/<DB Name>

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
    
# Development:
For ease of use during development, the docker-compose.yml file has been provided with all mounts listed. The image
that is brought up can be placed behind any proxy (nginx, apache, see below). However it is set to trust all headers
by default, this is dangerous and should only be used for development or in a highly controlled environment.

It is expected that the developer will user a docker-compose.override.yaml file to override any sensitive or incorrect
environmental variables. 

At this point the DB is not automatically populated when the containers come up. In the root of the source
code directory you can set the DATABASE_URL environmental variable to point to the container and run 'flask db upgrade'
this will populate the DB. For example:

        export DATABASE_URL=mysql+mysqlconnector://comodo_proxy:echee4yeloa0Iajienu9thahGhoo4x@localhost:8001/comodo_proxy
        flask db upgrade

# Creating a new production release:
Whenever a branch is merged into master and pushed github actions will create a new container that will be tagged with the short hash of the commit, as well as being tagged 'latest'. Simply put, unless something breaks, there is nothing for you to do to create a new release. 
