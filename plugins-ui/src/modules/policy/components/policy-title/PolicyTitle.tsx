import TokenPair from "@/modules/shared/token-pair/TokenPair";
import { TitleFieldProps } from "@rjsf/utils";

export function TitleFieldTemplate(props: TitleFieldProps) {
  const { id, title, registry } = props;

  let source_token_id = registry.formContext?.sourceTokenId;
  let destination_token_id = registry.formContext?.destinationTokenId;

  const editingForm = registry.formContext?.editing;

  return (
    <header style={{ fontSize: "2.125rem" }} id={id} data-testid={id}>
      {editingForm && source_token_id && destination_token_id && (
        <TokenPair data={[source_token_id, destination_token_id]} />
      )}

      {(!editingForm || !source_token_id || !destination_token_id) && title}
    </header>
  );
}
