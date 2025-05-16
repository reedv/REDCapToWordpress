<!-- DEPRECIATED, see issue #32 -->
<!--?php

include 'RedCap_API_to_Flask.php';

/*
    This is a simplified version of the profile page that displays
    all participant data in a table format for testing purposes.
*/

$record_id = $_GET['recordID'];

// Get all participant data from RedCap
$data = request_data($record_id);

// Start building the page
echo '<h1>Participant Data</h1>';
echo '<p>Record ID: ' . htmlspecialchars($record_id) . '</p>';

// Check if we have data
if (empty($data)) {
    echo '<p>No data found for this record ID.</p>';
    exit;
}

// Function to recursively display all data in a table
function display_data_table($data, $parent_key = '') {
    echo '<table border="1" cellpadding="5" cellspacing="0" style="margin-bottom: 20px;">';
    echo '<tr><th>Field</th><th>Value</th></tr>';
    
    foreach ($data as $key => $value) {
        $display_key = $parent_key ? "$parent_key.$key" : $key;
        
        if (is_array($value)) {
            echo '<tr>';
            echo '<td colspan="2"><strong>' . htmlspecialchars($display_key) . '</strong></td>';
            echo '</tr>';
            display_data_table($value, $display_key);
        } else {
            echo '<tr>';
            echo '<td>' . htmlspecialchars($display_key) . '</td>';
            echo '<td>' . htmlspecialchars($value) . '</td>';
            echo '</tr>';
        }
    }
    
    echo '</table>';
}

// Display all data
display_data_table($data);

// Add basic styling
echo '<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th { background-color: #f2f2f2; text-align: left; }
    tr:nth-child(even) { background-color: #f9f9f9; }
</style>';
?-->
