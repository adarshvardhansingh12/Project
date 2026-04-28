# Subdomain takeover fingerprints — full coverage
# Each entry defines a cloud service, its CNAME patterns, and HTTP response fingerprints
# that indicate the service is unclaimed / available for takeover

FINGERPRINTS = [

    # -------------------------------------------------------------------------
    # AWS
    # -------------------------------------------------------------------------
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
        "http_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "takeover_possible": True,
        "severity": "critical",
        "description": "S3 bucket referenced by CNAME does not exist and can be claimed by anyone.",
        "remediation": "Remove the dangling CNAME record or recreate the missing S3 bucket.",
        "references": "https://hackerone.com/reports/207599",
    },
    {
        "service": "AWS Elastic Beanstalk",
        "cname_patterns": ["elasticbeanstalk.com"],
        "http_fingerprints": ["404 Not Found", "No Application"],
        "takeover_possible": True,
        "severity": "critical",
        "description": "Elastic Beanstalk environment referenced by CNAME no longer exists.",
        "remediation": "Remove the CNAME record or re-deploy the Elastic Beanstalk environment.",
        "references": "https://edoverflow.com/2017/subdomain-takeover-via-aws-elastic-beanstalk/",
    },
    {
        "service": "AWS CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "http_fingerprints": ["The request could not be satisfied", "ERROR: The request could not be satisfied"],
        "takeover_possible": False,
        "severity": "low",
        "description": "CloudFront distribution CNAME detected. Manual verification needed.",
        "remediation": "Verify the CloudFront distribution is correctly configured and remove unused CNAME records.",
        "references": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html",
    },

    # -------------------------------------------------------------------------
    # GitHub
    # -------------------------------------------------------------------------
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "githubusercontent.com"],
        "http_fingerprints": [
            "There isn't a GitHub Pages site here",
            "404 There is no GitHub Pages site here",
        ],
        "takeover_possible": True,
        "severity": "high",
        "description": "GitHub Pages CNAME points to an unclaimed repository. Anyone can create the repo and serve arbitrary content.",
        "remediation": "Remove the CNAME record or create and configure the missing GitHub Pages repository.",
        "references": "https://hackerone.com/reports/263902",
    },

    # -------------------------------------------------------------------------
    # Microsoft Azure
    # -------------------------------------------------------------------------
    {
        "service": "Azure App Service",
        "cname_patterns": ["azurewebsites.net", "azure-api.net", "cloudapp.azure.com", "cloudapp.net"],
        "http_fingerprints": [
            "404 Web Site not found",
            "This Azure App Service is parked",
            "No web app was found for this domain",
        ],
        "takeover_possible": True,
        "severity": "critical",
        "description": "Azure App Service referenced by CNAME is unprovisioned and can be claimed.",
        "remediation": "Remove the dangling CNAME or re-provision the Azure App Service resource.",
        "references": "https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
    },
    {
        "service": "Azure Traffic Manager",
        "cname_patterns": ["trafficmanager.net"],
        "http_fingerprints": ["404 Not Found", "The page cannot be found"],
        "takeover_possible": True,
        "severity": "critical",
        "description": "Azure Traffic Manager profile CNAME is dangling and can be registered.",
        "remediation": "Remove the CNAME record or recreate the Traffic Manager profile.",
        "references": "https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
    },
    {
        "service": "Azure Blob Storage",
        "cname_patterns": ["blob.core.windows.net"],
        "http_fingerprints": ["The specified container does not exist", "BlobNotFound", "ContainerNotFound"],
        "takeover_possible": True,
        "severity": "critical",
        "description": "Azure Blob Storage container referenced by CNAME does not exist.",
        "remediation": "Remove the CNAME record or recreate the Blob Storage container.",
        "references": "https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
    },

    # -------------------------------------------------------------------------
    # Heroku
    # -------------------------------------------------------------------------
    {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokussl.com"],
        "http_fingerprints": ["No such app", "There's nothing here, yet.", "herokucdn.com/error-pages/no-such-app.html"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Heroku app referenced by CNAME no longer exists and the app name can be re-registered.",
        "remediation": "Remove the dangling CNAME or recreate the Heroku app with the original name.",
        "references": "https://hackerone.com/reports/159156",
    },

    # -------------------------------------------------------------------------
    # Netlify
    # -------------------------------------------------------------------------
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.app", "netlify.com"],
        "http_fingerprints": ["Not found - Request ID", "Page Not Found"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Netlify site CNAME points to an unclaimed site name that can be registered.",
        "remediation": "Remove the CNAME record or claim the Netlify site name.",
        "references": "https://community.netlify.com/t/subdomain-takeover/7609",
    },

    # -------------------------------------------------------------------------
    # Vercel
    # -------------------------------------------------------------------------
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "now.sh"],
        "http_fingerprints": ["The deployment could not be found", "404: NOT_FOUND"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Vercel deployment CNAME points to a project that no longer exists.",
        "remediation": "Remove the CNAME record or redeploy the Vercel project.",
        "references": "https://vercel.com/docs/concepts/projects/custom-domains",
    },

    # -------------------------------------------------------------------------
    # Fastly
    # -------------------------------------------------------------------------
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net", "fastlylb.net"],
        "http_fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "takeover_possible": True,
        "severity": "high",
        "description": "Fastly CDN CNAME is not linked to any active service and can be claimed.",
        "remediation": "Remove the CNAME record or reconfigure the Fastly service.",
        "references": "https://hackerone.com/reports/263310",
    },

    # -------------------------------------------------------------------------
    # Shopify
    # -------------------------------------------------------------------------
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "http_fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "Shopify store CNAME points to an unclaimed or suspended store.",
        "remediation": "Remove the CNAME record or reactivate the Shopify store.",
        "references": "https://hackerone.com/reports/159463",
    },

    # -------------------------------------------------------------------------
    # Tumblr
    # -------------------------------------------------------------------------
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "http_fingerprints": [
            "Whatever you were looking for doesn&#39;t currently exist at this address",
            "There's nothing here.",
        ],
        "takeover_possible": True,
        "severity": "medium",
        "description": "Tumblr custom domain CNAME points to a deleted or unclaimed blog.",
        "remediation": "Remove the CNAME record or reclaim the Tumblr blog.",
        "references": "https://edoverflow.com/2017/subdomain-takeover-via-tumblr/",
    },

    # -------------------------------------------------------------------------
    # WordPress.com
    # -------------------------------------------------------------------------
    {
        "service": "WordPress.com",
        "cname_patterns": ["wordpress.com", "wpcomstaging.com"],
        "http_fingerprints": ["Do you want to register", "doesn't exist"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "WordPress.com custom domain CNAME points to an unclaimed or deleted blog.",
        "remediation": "Remove the CNAME record or reclaim the WordPress.com blog.",
        "references": "https://hackerone.com/reports/422953",
    },

    # -------------------------------------------------------------------------
    # Ghost
    # -------------------------------------------------------------------------
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "http_fingerprints": ["The thing you were looking for is no longer here"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "Ghost blog CNAME points to an unclaimed or deleted Ghost.io site.",
        "remediation": "Remove the CNAME record or reclaim the Ghost.io blog.",
        "references": "https://hackerone.com/reports/264210",
    },

    # -------------------------------------------------------------------------
    # Zendesk
    # -------------------------------------------------------------------------
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "http_fingerprints": ["Help Center Closed", "Oops, this help center no longer exists"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Zendesk help center CNAME points to an unclaimed subdomain — impersonation risk.",
        "remediation": "Remove the CNAME record or reconfigure the Zendesk account.",
        "references": "https://hackerone.com/reports/114134",
    },

    # -------------------------------------------------------------------------
    # HubSpot
    # -------------------------------------------------------------------------
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.net", "hs-sites.com", "hubspotpagebuilder.com"],
        "http_fingerprints": ["This page isn&#39;t available", "does not exist in our system"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "HubSpot page CNAME points to an unclaimed or deleted HubSpot site.",
        "remediation": "Remove the CNAME record or reconfigure the HubSpot portal.",
        "references": "https://hackerone.com/reports/235822",
    },

    # -------------------------------------------------------------------------
    # Bitbucket
    # -------------------------------------------------------------------------
    {
        "service": "Bitbucket Pages",
        "cname_patterns": ["bitbucket.io"],
        "http_fingerprints": ["Repository not found", "The page you have requested does not exist"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Bitbucket Pages CNAME points to a deleted or unclaimed repository.",
        "remediation": "Remove the CNAME record or recreate the Bitbucket repository.",
        "references": "https://hackerone.com/reports/159108",
    },

    # -------------------------------------------------------------------------
    # Surge.sh
    # -------------------------------------------------------------------------
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "http_fingerprints": ["project not found", "This domain is not configured"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Surge.sh project CNAME is not linked to any active deployment.",
        "remediation": "Remove the CNAME record or redeploy to Surge.sh.",
        "references": "https://hackerone.com/reports/302462",
    },

    # -------------------------------------------------------------------------
    # Intercom
    # -------------------------------------------------------------------------
    {
        "service": "Intercom",
        "cname_patterns": ["intercom.io", "custom.intercom.help"],
        "http_fingerprints": ["This page is reserved for artistic dogs", "Uh oh. That page doesn"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "Intercom help site CNAME points to an unclaimed or deleted workspace.",
        "remediation": "Remove the CNAME record or reclaim the Intercom workspace.",
        "references": "https://hackerone.com/reports/202767",
    },

    # -------------------------------------------------------------------------
    # Pantheon
    # -------------------------------------------------------------------------
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io", "getpantheon.com"],
        "http_fingerprints": ["404 error unknown site!", "The gods are wise"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Pantheon hosting CNAME points to an unclaimed or deleted site.",
        "remediation": "Remove the CNAME record or reconfigure the Pantheon site.",
        "references": "https://hackerone.com/reports/303730",
    },

    # -------------------------------------------------------------------------
    # Readme.io
    # -------------------------------------------------------------------------
    {
        "service": "Readme.io",
        "cname_patterns": ["readme.io", "readmessl.com"],
        "http_fingerprints": ["Project doesnt exist... yet!"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "Readme.io documentation site CNAME points to an unclaimed project.",
        "remediation": "Remove the CNAME record or reclaim the Readme.io project.",
        "references": "https://hackerone.com/reports/182569",
    },

    # -------------------------------------------------------------------------
    # Strikingly
    # -------------------------------------------------------------------------
    {
        "service": "Strikingly",
        "cname_patterns": ["strikingly.com", "s.strikinglydns.com"],
        "http_fingerprints": ["But if you're looking to build your own website", "page not found"],
        "takeover_possible": True,
        "severity": "medium",
        "description": "Strikingly website CNAME points to an unclaimed site.",
        "remediation": "Remove the CNAME record or reclaim the Strikingly site.",
        "references": "https://hackerone.com/reports/170532",
    },

    # -------------------------------------------------------------------------
    # Google Cloud
    # -------------------------------------------------------------------------
    {
        "service": "Google Cloud Storage",
        "cname_patterns": ["storage.googleapis.com", "c.storage.googleapis.com"],
        "http_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "takeover_possible": True,
        "severity": "critical",
        "description": "Google Cloud Storage bucket referenced by CNAME does not exist and can be claimed.",
        "remediation": "Remove the dangling CNAME or recreate the GCS bucket.",
        "references": "https://hackerone.com/reports/302862",
    },
    {
        "service": "Google Firebase",
        "cname_patterns": ["firebaseapp.com", "web.app"],
        "http_fingerprints": ["The requested URL was not found on this server", "404. That&#39;s an error"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Firebase Hosting CNAME points to an unclaimed or deleted Firebase project.",
        "remediation": "Remove the CNAME record or reclaim the Firebase project.",
        "references": "https://hackerone.com/reports/410253",
    },

    # -------------------------------------------------------------------------
    # DigitalOcean
    # -------------------------------------------------------------------------
    {
        "service": "DigitalOcean App Platform",
        "cname_patterns": ["ondigitalocean.app"],
        "http_fingerprints": ["We couldn&#39;t find what you&#39;re looking for"],
        "takeover_possible": True,
        "severity": "high",
        "description": "DigitalOcean App Platform CNAME points to an unclaimed app.",
        "remediation": "Remove the CNAME record or reclaim the DigitalOcean app.",
        "references": "https://www.digitalocean.com/docs/app-platform/",
    },

    # -------------------------------------------------------------------------
    # Fly.io
    # -------------------------------------------------------------------------
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev", "fly.io"],
        "http_fingerprints": ["404 Not Found", "app not found"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Fly.io app CNAME points to an unclaimed application.",
        "remediation": "Remove the CNAME record or redeploy the Fly.io application.",
        "references": "https://fly.io/docs/reference/custom-domains/",
    },

    # -------------------------------------------------------------------------
    # Render
    # -------------------------------------------------------------------------
    {
        "service": "Render",
        "cname_patterns": ["onrender.com"],
        "http_fingerprints": ["Page Not Found", "The page you&#39;re looking for doesn&#39;t exist"],
        "takeover_possible": True,
        "severity": "high",
        "description": "Render service CNAME points to an unclaimed or deleted deployment.",
        "remediation": "Remove the CNAME record or redeploy the Render service.",
        "references": "https://render.com/docs/custom-domains",
    },

    # -------------------------------------------------------------------------
    # Squarespace
    # -------------------------------------------------------------------------
    {
        "service": "Squarespace",
        "cname_patterns": ["squarespace.com", "sqsp.net"],
        "http_fingerprints": ["No Such Account", "You need to assign a website to this domain"],
        "takeover_possible": False,
        "severity": "low",
        "description": "Squarespace CNAME detected. Takeover generally not possible but dangling record should be removed.",
        "remediation": "Remove the CNAME record if the Squarespace site is no longer active.",
        "references": "https://www.squarespace.com/help/content/connecting-a-domain-to-squarespace",
    },
]

# Quick lookup: total services covered
TOTAL_SERVICES = len(FINGERPRINTS)
SERVICE_NAMES = [f["service"] for f in FINGERPRINTS]
