import os
import time
import wave
import string


def check_audio_boundary(audio_sample, next_bytes):
    if len(next_bytes) < 16:
        return True
    orig_diff = sum(abs(audio_sample[i] - audio_sample[i + 1]) for i in range(len(audio_sample) - 1)) / len(audio_sample)
    next_diff = sum(abs(next_bytes[i] - next_bytes[i + 1]) for i in range(len(next_bytes) - 1)) / len(next_bytes)

    if orig_diff > 0 and next_diff > 0:
        ratio = max(orig_diff, next_diff) / min(orig_diff, next_diff)
        if ratio > 5.0:
            return True
    elif next_diff == 0:
        return True
    return False


def steganography_analysis(stego_wav):
    try:
        audio = wave.open(stego_wav, 'rb')
        frames = bytearray(list(audio.readframes(audio.getnframes())))
        audio.close()

        extracted_bits = ""
        for i in range(len(frames)):
            extracted_bits += str(frames[i] & 1)

        all_bytes = [
            extracted_bits[i:i + 8]
            for i in range(0, len(extracted_bits), 8)
        ]

        decoded_msg = ""
        printable_chars = set(string.printable)

        for b in all_bytes:
            if len(b) == 8:
                char = chr(int(b, 2))
                decoded_msg += char

                if len(decoded_msg) == 30:
                    garbage_count = sum(
                        1 for c in decoded_msg
                        if c not in printable_chars or ord(c) < 32
                    )
                    if garbage_count > 5:
                        return "No secret messages found in this file!"

                if "###" in decoded_msg:
                    return decoded_msg.split("###")[0]

        return "No secret messages found in this file!"

    except Exception as e:
        return f"Oops! Something went wrong: {e}"


def carving_process(disk_path, output_folder):
    start_time = time.time()

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    signatures = [
        (b'RIFF', '.wav'),
        (b'GIF89a', '.gif'),
        (b'GIF87a', '.gif'),
    ]

    with open(disk_path, 'rb') as f:
        disk_data = f.read()
        disk_size = len(disk_data)
        found_files_count = 0

        for sig, ext in signatures:
            start = 0
            print(f"- Searching for {ext.upper()} files...")

            while True:
                head_offset = disk_data.find(sig, start)
                if head_offset == -1:
                    break

                found_files_count += 1
                start = head_offset + 1

                if ext == '.wav':
                    f.seek(head_offset)
                    head_sample = f.read(500)
                    declared_size = int.from_bytes(head_sample[4:8], 'little') + 8

                    f.seek(head_offset + 500)
                    next_bytes = f.read(200)
                    is_fragmented = all(b == 0 for b in next_bytes)

                    if not is_fragmented:
                        print(f"    [+] Normal WAV Detected at {hex(head_offset)}")
                        f.seek(head_offset)
                        final_data = f.read(declared_size)
                    else:
                        print(f"    [!] Fragmented WAV Detected at {hex(head_offset)}! Adjusting Tail...")
                        search_start = head_offset + 500
                        found_tail = False
                        tail_data = b""

                        f.seek(search_start)
                        while f.tell() < disk_size:
                            chunk = f.read(65536)
                            if not chunk:
                                break

                            for j in range(len(chunk)):
                                if chunk[j] != 0x00 and chunk[j] != 0xFF:
                                    potential_tail_offset = f.tell() - len(chunk) + j

                                    if potential_tail_offset > (head_offset + 5000):
                                        f.seek(potential_tail_offset)

                                        block_size = 4096
                                        while f.tell() < disk_size:
                                            current_block = f.read(block_size)
                                            if not current_block:
                                                break

                                            if check_audio_boundary(head_sample[400:500], current_block[:100]):
                                                break

                                            tail_data += current_block
                                            if len(tail_data) >= (declared_size - 500):
                                                break

                                        final_data = head_sample + tail_data
                                        found_tail = True
                                        break
                            if found_tail:
                                break

                else:
                    print(f"    [+] GIF Detected at {hex(head_offset)}. Extracting full block...")
                    f.seek(head_offset)
                    final_data = f.read(1024 * 1024)

                file_name = f"Recovered_{found_files_count}{ext}"
                with open(os.path.join(output_folder, file_name), "wb") as out:
                    out.write(final_data)
                print(f"    Saved as: {file_name} at offset {hex(head_offset)}")

    end_time = time.time()
    print("-" * 40)
    print(f"- [✔] PERFECT SUCCESS! ALL FILES RECOVERED CLEANLY :)")
    print(f"- Total Files Recovered: {found_files_count}")
    print(f"- Execution Time: {round(end_time - start_time, 4)} seconds")
    print("-" * 40)


if __name__ == "__main__":
    target_disk = input("Enter the forensic image path: ")
    output_dir = "recovered_files"

    print("=" * 55)
    print("Executing Binary Media Carving Process...")
    print("=" * 55)
    carving_process(target_disk, output_dir)

    print("\n" + "=" * 55)
    print("Executing Steganography Analysis on Recovered Files")
    print("=" * 55)

    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)

        if filename.lower().endswith(".wav"):
            result = steganography_analysis(file_path)
            print(f"\nAnalyzing File: {filename}")
            print("-" * 55)
            print("The Result:")
            print(">>", result)

    print("\nAnalysis completed successfully.")