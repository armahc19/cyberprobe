
     window.onload = function() {
    document.getElementById('popup').style.display = 'block';
    }
    
    function closePopup() {
        document.getElementById('popup').style.display = 'none';
    }
    
    function joinWebinar() {
        // Add any tracking code here if needed
        console.log('User clicked webinar link');
    }
    
    // Close popup when clicking outside the content
    document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('popup').addEventListener('click', function(e) {
            if (e.target === this) {
                closePopup();
            }
        });
    
        // Close popup with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closePopup();
            }
        });
    });