scanner_patterns = [
    (['S', 'RA', 'S', 'SA', 'A', 'RA'], 'Angry IP scanner', 'Open'),
    ([('S', 64240), 'RA', ('S', 64240), 'RA'], 'Angry IP scanner', 'Closed'),
    (['S', 'SA', 'R', 'R'], 'Masscan', 'Open'),
    (['S', 'RA', 'R'], 'Masscan', 'Closed'),
    (['S', 'SA', 'R'], 'nmap / zmap scanner', 'Open'),
    (['S', 'RA'], 'nmap / zmap scanner', 'Closed'),
]

def pattern_match(flag_sequence, pattern):
    if len(flag_sequence) != len(pattern):
        return False
    
    for i, flag in enumerate(flag_sequence):
        # Check if the pattern at this index is a tuple (flag, window_size)
        if isinstance(pattern[i], tuple):
            # Check if the flag matches and the window size matches
            if isinstance(flag, tuple):
                if flag[0] != pattern[i][0] or flag[1] != pattern[i][1]:
                    return False
            else:
                # Pattern expects a window size, but incoming flag doesn't have it
                return False
        else:
            # Pattern is just a flag, compare only flags
            # Extract flag from incoming packet if it's a tuple (flag, window_size)
            incoming_flag = flag[0] if isinstance(flag, tuple) else flag
            if incoming_flag != pattern[i]:
                return False
    return True