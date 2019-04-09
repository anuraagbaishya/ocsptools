$(document).ready(function () {

    if(document.location.pathname.match(/index\.html/)) {
        $("#ocsp-submit-button").click(function (event) {

            event.preventDefault();
            var form = $('#certificate-input-form')[0];
            var data = new FormData(form);
            data.append("action", "Check OCSP Response");

            $.ajax({
                type: "POST",
                enctype: 'multipart/form-data',
                url: "response-check",
                data: data,
                processData: false,
                contentType: false,
                cache: false,
                timeout: 600000,
                success: function (data) {

                    localStorage.setItem('ocsp-response', data);
                    window.location.replace("/response");

                },
                error: function (e) {

                    console.log("ERROR : ", e);

                }
            });

        });
    }
    
    else if(document.location.pathname.match(/response\.html/)){
        
        var json_response = localStorage.getItem('ocsp-response');
        var json_obj = JSON.parse(json_response)

        for (var key in json_obj){
            if (json_obj.hasOwnProperty(key)){
                console.log(key + ":" + json_obj[key]);
            }
        }


    }

});