// Lazy load social media widgets to improve initial page load
function loadFacebookWidget() {
    const container = document.getElementById('facebook-widget');
    container.innerHTML = '<div class="fb-page" data-href="https://www.facebook.com/bluecrestcollege.ghana" data-tabs="timeline" data-width="" data-height="350" data-small-header="true" data-adapt-container-width="true" data-hide-cover="true" data-show-facepile="true"><blockquote cite="https://www.facebook.com/bluecrestcollege.ghana" class="fb-xfbml-parse-ignore"><a href="https://www.facebook.com/bluecrestcollege.ghana">Bluecrest College, Ghana</a></blockquote></div>';
    
    // Load Facebook SDK
    if (!document.getElementById('facebook-jssdk')) {
        const js = document.createElement('script');
        js.id = 'facebook-jssdk';
        js.src = 'https://connect.facebook.net/en_US/sdk.js#xfbml=1&version=v18.0';
        document.head.appendChild(js);
    }
}

function loadInstagramWidget() {
    const container = document.getElementById('instagram-widget');
    container.innerHTML = '<iframe src="https://cdn.lightwidget.com/widgets/6d913a6ef2df5fa6ac4399563d76ee0f.html" scrolling="no" allowtransparency="true" class="lightwidget-widget" style="width:100%;border:0;overflow:hidden;" loading="lazy"></iframe>';
    
    // Load Instagram widget script if not already loaded
    if (!document.querySelector('script[src="https://cdn.lightwidget.com/widgets/lightwidget.js"]')) {
        const script = document.createElement('script');
        script.src = 'https://cdn.lightwidget.com/widgets/lightwidget.js';
        document.head.appendChild(script);
    }
}

function loadTwitterWidget() {
    const container = document.getElementById('twitter-widget');
    container.innerHTML = '<a class="twitter-timeline" data-height="350" data-theme="light" data-link-color="#2B7BB9" href="https://twitter.com/bluecrestghana?ref_src=twsrc%5Etfw">Tweets by bluecrestghana</a>';
    
    // Load Twitter widget script if not already loaded
    if (!document.querySelector('script[src="https://platform.twitter.com/widgets.js"]')) {
        const script = document.createElement('script');
        script.src = 'https://platform.twitter.com/widgets.js';
        script.charset = 'utf-8';
        script.async = true;
        document.head.appendChild(script);
    }
}

// Auto-load social widgets when they come into view (Intersection Observer)
document.addEventListener('DOMContentLoaded', function() {
    if ('IntersectionObserver' in window) {
        const socialObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const widget = entry.target.dataset.widget;
                    switch(widget) {
                        case 'facebook':
                            loadFacebookWidget();
                            break;
                        case 'instagram':
                            loadInstagramWidget();
                            break;
                        case 'twitter':
                            loadTwitterWidget();
                            break;
                    }
                    socialObserver.unobserve(entry.target);
                }
            });
        }, { rootMargin: '100px' });

        // Observe social media widgets
        document.querySelectorAll('.social-widget-placeholder').forEach(widget => {
            socialObserver.observe(widget);
        });
    } else {
        // Fallback for browsers without Intersection Observer
        setTimeout(() => {
            loadFacebookWidget();
            loadInstagramWidget();
            loadTwitterWidget();
        }, 3000);
    }
});