<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") 
{
    // Get form data
    $name = $_POST["name"];
    $usn = $_POST["usn"];
    $sem = $_POST["sem"];
    $assignments = isset($_POST["assignment"]) ? implode(", ", $_POST["assignment"]) : "None selected";
    $subject = $_POST["subject"];
    $message = $_POST["message"];
    $submissionType = $_POST["submission_type"];  // Get the selected radio button value

    // Handle file upload
    $fileName = $_FILES["uploadfile"]["name"];
    if (file_exists($fileName)) 
        $uploadMessage = "File already exists: $fileName";
    else
    {
        move_uploaded_file($_FILES["uploadfile"]["tmp_name"], $_FILES["uploadfile"]["name"]);
        $uploadMessage = "Uploaded File: $fileName";
    }

    // Display submitted data
    echo "<h2>Submitted Data:</h2>";
    echo "Name: $name<br>";
    echo "USN: $usn<br>";
    echo "Sem: $sem<br>";
    echo "Assignments: $assignments<br>";
    echo "Subject: $subject<br>";
    echo "Message: $message<br>";
    echo "Submission Type: $submissionType<br>";  // Display the submission type (Online or Physical)
    echo "File: $uploadMessage<br>";
} 
else 
    echo "No form submitted.";
?>
