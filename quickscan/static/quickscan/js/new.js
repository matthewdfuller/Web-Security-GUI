//Display an error message using the modal
function displayError(error_msg) {
    $("#modal_error_msg").text(error_msg);
    $('#myModal').modal('show');
}

//Scan button is clicked
$("#begin-scan").click(function() {
    var errors = false;
    var url_entered = $("#url_entered").val();
    
    //Textbox was empty
    if(url_entered.length < 4) {
        displayError("Please enter a valid URL or IP address.")
        errors = true;
    }
    
    //If no errors in form, attempt connection to site
    if(errors == false) {
        $("#new-scan-form").submit();
    }
});