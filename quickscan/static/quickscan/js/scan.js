//Display an error message
function displayError(error_msg) {
    alert(error_msg);
}

//Expand / collapse buttons
$("#expand-all").click(function() {
    $('.results-collapse').each(function() {
        $(this).collapse('show');
    });
});
$("#collapse-all").click(function() {
    $('.results-collapse').each(function() {
        $(this).collapse('hide');
    });
});

//POST to receive scan results. "Data" is set to '0' by template if scan is finished running.
//'1' is for if the scan is still running so when it is finished, the page can refresh with the data.
$(document).ready(function() {
    if(data == 1) {
        $.post('/scan/', {
            csrfmiddlewaretoken: csrfmiddlewaretoken,
            scan_uuid: scan_uuid
            },
            function(data) {
                document.location.reload(true);
        }, 'json');
    }
});