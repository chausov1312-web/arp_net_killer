import subprocess

def run_fzf(options, prompt, multi=False):
    """Запуск fzf для выбора (одиночного или множественного)"""
    try:
        cmd = ['fzf', '--reverse', '--height=40%', '--prompt', prompt]
        if multi:
            cmd.append('--multi')
        
        result = subprocess.run(
            cmd,
            input='\n'.join(options),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            if multi:
                return [line.strip() for line in result.stdout.strip().split('\n') if line]
            return result.stdout.strip()
    except:
        if multi:
            return simple_multi_select(options, prompt)
        return simple_select(options, prompt)
    return None

def simple_select(options, prompt):
    """Простой выбор если fzf не доступен"""
    print(f"\n{prompt}:")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    try:
        choice = int(input("Выберите номер: ")) - 1
        return options[choice]
    except:
        return None

def simple_multi_select(options, prompt):
    """Простой множественный выбор если fzf не доступен"""
    print(f"\n{prompt} (введите номера через пробел):")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    try:
        choices = input("Выберите номера: ").split()
        selected = []
        for choice in choices:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                selected.append(options[idx])
        return selected
    except:
        return []
